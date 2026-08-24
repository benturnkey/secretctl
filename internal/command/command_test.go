package command

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

type fakeSecretsClient struct {
	initResult           *turnkeyapi.InitImportSecretsResult
	initErr              error
	initOrganizationID   string
	importResult         *turnkeyapi.ImportSecretsResult
	importErr            error
	importOrganizationID string
	imported             *turnkeyapi.ImportSecretParams
	listFn               func(turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error)
}

func (f *fakeSecretsClient) InitImportSecrets(_ context.Context, organizationID string) (*turnkeyapi.InitImportSecretsResult, error) {
	f.initOrganizationID = organizationID
	return f.initResult, f.initErr
}

func (f *fakeSecretsClient) ImportSecrets(_ context.Context, organizationID string, secret turnkeyapi.ImportSecretParams) (*turnkeyapi.ImportSecretsResult, error) {
	f.importOrganizationID = organizationID
	f.imported = &secret
	return f.importResult, f.importErr
}

func (f *fakeSecretsClient) ListSecrets(_ context.Context, request turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error) {
	if f.listFn == nil {
		return nil, errors.New("unexpected ListSecrets call")
	}
	return f.listFn(request)
}

func testDependencies(client secretsClient, environment map[string]string) dependencies {
	return dependencies{
		lookupEnv: func(name string) (string, bool) {
			value, exists := environment[name]
			return value, exists
		},
		newClient: func(_, _ string) (secretsClient, error) {
			return client, nil
		},
		parseSigner: func(string) (*ecdsa.PublicKey, error) {
			return &ecdsa.PublicKey{}, nil
		},
		encrypt: func(plaintext []byte, target, organizationID string, _ *ecdsa.PublicKey) (string, string, error) {
			if target != "target" || organizationID != "org_test" {
				return "", "", errors.New("unexpected encryption arguments")
			}
			if !strings.Contains(string(plaintext), `"EMPTY":""`) {
				return "", "", errors.New("expected empty value in plaintext")
			}
			return "encrypted-payload", "target-public", nil
		},
	}
}

func TestCreateAllowEmptyValues(t *testing.T) {
	t.Parallel()

	client := &fakeSecretsClient{
		initResult:   &turnkeyapi.InitImportSecretsResult{EnclaveTargetMessages: []string{"target"}},
		importResult: &turnkeyapi.ImportSecretsResult{SecretIDs: []string{"secret_test"}},
	}
	environment := map[string]string{
		"TURNKEY_API_PRIVATE_KEY":   "api-private-key",
		"TURNKEY_SIGNER_PUBLIC_KEY": "signer-public-key",
		"EMPTY":                     "",
	}
	deps := testDependencies(client, environment)

	root := newRootCommand(deps)
	root.SetArgs([]string{"create", "--org-id", "org_test", "--from-env", "EMPTY"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("expected empty environment value to be rejected")
	}

	var output bytes.Buffer
	root = newRootCommand(deps)
	root.SetArgs([]string{
		"create", "--org-id", "org_test", "--name", "test-name", "--property", "kind=test",
		"--from-env", "EMPTY", "--allow-empty-values",
	})
	root.SetOut(&output)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("create command error = %v", err)
	}
	if strings.Contains(output.String(), `"EMPTY"`) {
		t.Fatalf("create output leaked plaintext key: %s", output.String())
	}
	if !strings.Contains(output.String(), `"secret_id": "secret_test"`) {
		t.Fatalf("create output missing secret ID: %s", output.String())
	}
	if client.imported == nil || client.imported.SecretPayload != "encrypted-payload" {
		t.Fatalf("imported params = %#v", client.imported)
	}
	if client.initOrganizationID != "org_test" || client.importOrganizationID != "org_test" {
		t.Fatalf(
			"organization IDs: init = %q, import = %q",
			client.initOrganizationID,
			client.importOrganizationID,
		)
	}
}

func TestLoadConfigurationUsesEnvironmentProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		environment   string
		wantBaseURL   string
		wantSignerKey string
	}{
		{
			name:          "dev",
			environment:   "dev",
			wantBaseURL:   "https://api.dev.turnkey.engineering",
			wantSignerKey: "048cf9ed5f579298cc1571823a3222b82d80c529c551f6070fbe712ae1a9e8d1a23b7006e306d27190358dfcd9c44624918a00f23c920a33cb14f5b026eafc865d",
		},
		{
			name:          "preprod",
			environment:   "preprod",
			wantBaseURL:   "https://api.preprod.turnkey.engineering",
			wantSignerKey: "04f3422b8afbe425d6ece77b8d2469954715a2ff273ab7ac89f1ed70e0a9325eaa1698b4351fd1b23734e65c0b6a86b62dd49d70b37c94606aac402cbd84353212",
		},
		{
			name:          "prod",
			environment:   "prod",
			wantBaseURL:   "https://api.turnkey.com",
			wantSignerKey: "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeSecretsClient{}
			deps := testDependencies(client, map[string]string{
				"TURNKEY_API_PRIVATE_KEY": "api-private-key",
			})
			var gotPrivateKey, gotBaseURL, gotSignerKey string
			deps.newClient = func(privateKey, baseURL string) (secretsClient, error) {
				gotPrivateKey = privateKey
				gotBaseURL = baseURL
				return client, nil
			}
			deps.parseSigner = func(signerKey string) (*ecdsa.PublicKey, error) {
				gotSignerKey = signerKey
				return &ecdsa.PublicKey{}, nil
			}

			gotClient, _, err := loadConfiguration(deps, test.environment)
			if err != nil {
				t.Fatalf("load configuration: %v", err)
			}
			if gotClient != client {
				t.Fatal("load configuration returned the wrong client")
			}
			if gotPrivateKey != "api-private-key" {
				t.Fatalf("private key = %q, want api-private-key", gotPrivateKey)
			}
			if gotBaseURL != test.wantBaseURL {
				t.Fatalf("base URL = %q, want %q", gotBaseURL, test.wantBaseURL)
			}
			if gotSignerKey != test.wantSignerKey {
				t.Fatalf("signer key = %q, want %q", gotSignerKey, test.wantSignerKey)
			}
		})
	}
}

func TestLoadConfigurationEnvironmentOverridesProfile(t *testing.T) {
	t.Parallel()

	client := &fakeSecretsClient{}
	deps := testDependencies(client, map[string]string{
		"TURNKEY_API_PRIVATE_KEY":   "api-private-key",
		"TURNKEY_API_BASE_URL":      "https://turnkey.example.test",
		"TURNKEY_SIGNER_PUBLIC_KEY": "override-signer-key",
	})
	var gotBaseURL, gotSignerKey string
	deps.newClient = func(_ string, baseURL string) (secretsClient, error) {
		gotBaseURL = baseURL
		return client, nil
	}
	deps.parseSigner = func(signerKey string) (*ecdsa.PublicKey, error) {
		gotSignerKey = signerKey
		return &ecdsa.PublicKey{}, nil
	}

	if _, _, err := loadConfiguration(deps, "dev"); err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	if gotBaseURL != "https://turnkey.example.test" {
		t.Fatalf("base URL = %q, want override", gotBaseURL)
	}
	if gotSignerKey != "override-signer-key" {
		t.Fatalf("signer key = %q, want override", gotSignerKey)
	}
}

func TestListOrganizationIDConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		args               []string
		environmentOrgID   string
		wantOrganizationID string
		wantBaseURL        string
	}{
		{
			name:               "environment fallback",
			args:               []string{"list", "--env", "preprod"},
			environmentOrgID:   "org_from_environment",
			wantOrganizationID: "org_from_environment",
			wantBaseURL:        "https://api.preprod.turnkey.engineering",
		},
		{
			name:               "flag overrides environment",
			args:               []string{"list", "--env", "dev", "--org-id", "org_from_flag"},
			environmentOrgID:   "org_from_environment",
			wantOrganizationID: "org_from_flag",
			wantBaseURL:        "https://api.dev.turnkey.engineering",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotOrganizationID, gotBaseURL string
			client := &fakeSecretsClient{listFn: func(request turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error) {
				gotOrganizationID = request.OrganizationID
				return &turnkeyapi.ListSecretsResponse{}, nil
			}}
			deps := testDependencies(client, map[string]string{
				"TURNKEY_API_PRIVATE_KEY": "api-private-key",
				"TURNKEY_ORGANIZATION_ID": test.environmentOrgID,
			})
			deps.newClient = func(_ string, baseURL string) (secretsClient, error) {
				gotBaseURL = baseURL
				return client, nil
			}

			root := newRootCommand(deps)
			root.SetArgs(test.args)
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("list command: %v", err)
			}
			if gotOrganizationID != test.wantOrganizationID {
				t.Fatalf("organization ID = %q, want %q", gotOrganizationID, test.wantOrganizationID)
			}
			if gotBaseURL != test.wantBaseURL {
				t.Fatalf("base URL = %q, want %q", gotBaseURL, test.wantBaseURL)
			}
		})
	}
}

func TestOrganizationIDFlagDoesNotFallBackWhenExplicitlyEmpty(t *testing.T) {
	t.Parallel()

	deps := testDependencies(&fakeSecretsClient{}, map[string]string{
		"TURNKEY_API_PRIVATE_KEY": "api-private-key",
		"TURNKEY_ORGANIZATION_ID": "org_from_environment",
	})
	root := newRootCommand(deps)
	root.SetArgs([]string{"list", "--org-id="})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected explicitly empty --org-id to fail")
	}
	if err.Error() != "--org-id must not be empty" {
		t.Fatalf("error = %q, want empty --org-id error", err)
	}
}

func TestEnvironmentFlagRejectsUnsupportedValue(t *testing.T) {
	t.Parallel()

	root := newRootCommand(testDependencies(&fakeSecretsClient{}, nil))
	root.SetArgs([]string{"list", "--env", "staging", "--org-id", "org_test"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected unsupported environment to fail")
	}
	if err.Error() != "--env must be dev, preprod, or prod" {
		t.Fatalf("error = %q, want environment validation error", err)
	}
}

func TestListFiltersAcrossPages(t *testing.T) {
	t.Parallel()

	requests := make([]turnkeyapi.ListSecretsRequest, 0, 2)
	client := &fakeSecretsClient{}
	client.listFn = func(request turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error) {
		requests = append(requests, request)
		if len(requests) == 1 {
			secrets := make([]turnkeyapi.SecretMetadata, 100)
			for index := range secrets {
				secrets[index] = turnkeyapi.SecretMetadata{
					SecretID:        "secret_" + strconv.Itoa(index),
					CreatedAtUnixMs: "1000",
					StaticProperties: []turnkeyapi.KeyValue{
						{Key: "kind", Value: "other"},
					},
				}
			}
			secrets[50].StaticProperties[0].Value = "match"
			return &turnkeyapi.ListSecretsResponse{Secrets: secrets}, nil
		}
		if request.PaginationOptions.After == nil || *request.PaginationOptions.After != "secret_99" {
			return nil, fmt.Errorf("unexpected second-page cursor: %#v", request.PaginationOptions.After)
		}
		name := "second"
		return &turnkeyapi.ListSecretsResponse{Secrets: []turnkeyapi.SecretMetadata{
			{
				SecretID:        "secret_100",
				Name:            &name,
				CreatedAtUnixMs: "2000",
				StaticProperties: []turnkeyapi.KeyValue{
					{Key: "environment", Value: "prod"},
					{Key: "kind", Value: "match"},
				},
			},
		}}, nil
	}
	deps := testDependencies(client, map[string]string{"TURNKEY_API_PRIVATE_KEY": "key"})

	var output bytes.Buffer
	root := newRootCommand(deps)
	root.SetArgs([]string{"list", "--org-id", "org_test", "--property", "kind=match", "--limit", "2", "--format", "json"})
	root.SetOut(&output)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("list command error = %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("ListSecrets requests = %d, want 2", len(requests))
	}
	if strings.Count(output.String(), `"secret_id"`) != 2 {
		t.Fatalf("list output = %s", output.String())
	}
	if !strings.Contains(output.String(), `"environment": "prod"`) {
		t.Fatalf("list output missing properties: %s", output.String())
	}
}

func TestListTableOutput(t *testing.T) {
	t.Parallel()

	client := &fakeSecretsClient{listFn: func(turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error) {
		return &turnkeyapi.ListSecretsResponse{Secrets: []turnkeyapi.SecretMetadata{
			{
				SecretID:        "secret_test",
				CreatedAtUnixMs: "0",
				StaticProperties: []turnkeyapi.KeyValue{
					{Key: "z", Value: "last"},
					{Key: "a", Value: "first"},
				},
			},
		}}, nil
	}}
	deps := testDependencies(client, map[string]string{"TURNKEY_API_PRIVATE_KEY": "key"})

	var output bytes.Buffer
	root := newRootCommand(deps)
	root.SetArgs([]string{"list", "--org-id", "org_test"})
	root.SetOut(&output)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("list command error = %v", err)
	}
	if !strings.Contains(output.String(), "1970-01-01T00:00:00Z") || !strings.Contains(output.String(), "a=first,z=last") {
		t.Fatalf("unexpected table output: %s", output.String())
	}
}

func TestExecuteWritesStructuredSanitizedErrors(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		"TURNKEY_API_PRIVATE_KEY":   "api-private-key",
		"TURNKEY_SIGNER_PUBLIC_KEY": "signer-public-key",
		"SECRET":                    "plaintext-must-not-appear",
	}
	client := &fakeSecretsClient{initErr: errors.New("plaintext-must-not-appear")}
	deps := testDependencies(client, environment)

	var stdout, stderr bytes.Buffer
	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"create", "--org-id", "org_test", "--from-env", "SECRET"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		deps,
	)
	if exitCode != 6 {
		t.Fatalf("exit code = %d, want 6", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), "plaintext-must-not-appear") {
		t.Fatalf("stderr leaked plaintext: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"code":"IMPORT_FAILED"`) {
		t.Fatalf("stderr missing structured error code: %s", stderr.String())
	}
}

func TestExecuteClassifiesInvalidArguments(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := executeWithDependencies(
		context.Background(),
		[]string{"unknown-command"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		testDependencies(&fakeSecretsClient{}, nil),
	)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `"code":"PAYLOAD_INVALID"`) {
		t.Fatalf("stderr missing structured error code: %s", stderr.String())
	}
}
