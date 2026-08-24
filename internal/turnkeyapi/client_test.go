package turnkeyapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingStamper struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (s *recordingStamper) Stamp(body []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	return "test-stamp", nil
}

func TestClientSecretLifecycleRequests(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	getActivityCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-Stamp"); got != "test-stamp" {
			t.Errorf("X-Stamp = %q, want test-stamp", got)
		}
		if got := request.Header.Get("X-Client-Version"); got != "secretctl/0.1.0" {
			t.Errorf("X-Client-Version = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/public/v1/submit/init_import_secrets":
			if !strings.Contains(string(body), `"numSecrets":1`) || !strings.Contains(string(body), TransportEncryptionSuiteEnclaveEncryptV1) {
				t.Errorf("unexpected init body: %s", body)
			}
			_, _ = writer.Write([]byte(`{"activity":{"id":"activity_init","status":"ACTIVITY_STATUS_COMPLETED","result":{"initImportSecretsResult":{"enclaveTargetMessages":["target"]}}}}`))
		case "/public/v1/submit/import_secrets":
			if strings.Contains(string(body), "plaintext") {
				t.Error("import request contains plaintext")
			}
			_, _ = writer.Write([]byte(`{"activity":{"id":"activity_import","status":"ACTIVITY_STATUS_PENDING","result":{}}}`))
		case "/public/v1/query/get_activity":
			mu.Lock()
			getActivityCalls++
			mu.Unlock()
			_, _ = writer.Write([]byte(`{"activity":{"id":"activity_import","status":"ACTIVITY_STATUS_COMPLETED","result":{"importSecretsResult":{"secretIds":["secret_test"]}}}}`))
		case "/public/v1/query/list_secrets":
			_, _ = writer.Write([]byte(`{"secrets":[{"secretId":"secret_test","name":"name","createdAtUnixMs":"1000","staticProperties":[{"key":"kind","value":"test"}]}]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	stamper := &recordingStamper{}
	client, err := NewClient(
		server.URL,
		stamper,
		WithHTTPClient(server.Client()),
		WithPollConfig(time.Millisecond, time.Second),
		WithClock(func() time.Time { return time.UnixMilli(1234) }),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	initResult, err := client.InitImportSecrets(context.Background(), "org_test")
	if err != nil {
		t.Fatalf("InitImportSecrets() error = %v", err)
	}
	if got := initResult.EnclaveTargetMessages[0]; got != "target" {
		t.Fatalf("target = %q, want target", got)
	}
	importResult, err := client.ImportSecrets(context.Background(), "org_test", ImportSecretParams{
		SecretPayload:   "encrypted",
		TargetPublicKey: "target-key",
		EncryptionSuite: TransportEncryptionSuiteEnclaveEncryptV1,
	})
	if err != nil {
		t.Fatalf("ImportSecrets() error = %v", err)
	}
	if got := importResult.SecretIDs[0]; got != "secret_test" {
		t.Fatalf("secret ID = %q, want secret_test", got)
	}
	listResult, err := client.ListSecrets(context.Background(), ListSecretsRequest{OrganizationID: "org_test"})
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if got := listResult.Secrets[0].SecretID; got != "secret_test" {
		t.Fatalf("listed secret ID = %q, want secret_test", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if getActivityCalls != 1 {
		t.Fatalf("get activity calls = %d, want 1", getActivityCalls)
	}
}

func TestClientSanitizesResponseErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"code":6,"message":"secret value must never escape"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, &recordingStamper{}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.ListSecrets(context.Background(), ListSecretsRequest{OrganizationID: "org_test"})
	if err == nil {
		t.Fatal("expected response error")
	}
	if strings.Contains(err.Error(), "secret value") {
		t.Fatalf("error leaked response message: %v", err)
	}
	if !IsAlreadyExists(err) {
		t.Fatalf("expected already-exists classification: %v", err)
	}
}

func TestClientActivityFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"activity":{"id":"activity_failed","status":"ACTIVITY_STATUS_FAILED","failure":{"code":3,"message":"sensitive"},"result":{}}}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, &recordingStamper{}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.InitImportSecrets(context.Background(), "org_test")
	if err == nil {
		t.Fatal("expected activity failure")
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error leaked activity failure message: %v", err)
	}
	if !IsInvalidArgument(err) {
		t.Fatalf("expected invalid-argument classification: %v", err)
	}
}

func TestNewClientValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewClient("", nil); err == nil {
		t.Fatal("expected nil stamper to be rejected")
	}
	_, err := NewClient("", &recordingStamper{}, WithPollConfig(0, time.Second))
	if err == nil {
		t.Fatal("expected zero polling interval to be rejected")
	}
}

func TestActivityFeatureDisabledClassification(t *testing.T) {
	t.Parallel()

	err := &ActivityError{Status: activityStatusFailed, RPCCode: 9, message: "Secrets feature is not enabled"}
	if !IsFeatureDisabled(err) {
		t.Fatal("expected activity failure to be classified as feature disabled")
	}
	if strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("activity error leaked backend message: %v", err)
	}
}

func TestRequestTimestamp(t *testing.T) {
	t.Parallel()

	stamper := &recordingStamper{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"activity":{"id":"activity_init","status":"ACTIVITY_STATUS_COMPLETED","result":{"initImportSecretsResult":{"enclaveTargetMessages":["target"]}}}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, stamper, WithHTTPClient(server.Client()), WithClock(func() time.Time { return time.UnixMilli(4321) }))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.InitImportSecrets(context.Background(), "org_test"); err != nil {
		t.Fatalf("InitImportSecrets() error = %v", err)
	}
	stamper.mu.Lock()
	defer stamper.mu.Unlock()
	var request map[string]any
	if err := json.Unmarshal(stamper.bodies[0], &request); err != nil {
		t.Fatalf("decode stamped request: %v", err)
	}
	if got := request["timestampMs"]; got != "4321" {
		t.Fatalf("timestampMs = %#v, want 4321", got)
	}
}
