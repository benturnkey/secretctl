package command

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tkhq/secretctl/internal/secretcrypto"
	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

type secretsClient interface {
	InitImportSecrets(context.Context, string) (*turnkeyapi.InitImportSecretsResult, error)
	ImportSecrets(context.Context, string, turnkeyapi.ImportSecretParams) (*turnkeyapi.ImportSecretsResult, error)
	ListSecrets(context.Context, turnkeyapi.ListSecretsRequest) (*turnkeyapi.ListSecretsResponse, error)
}

type clientFactory func(privateKey, baseURL string) (secretsClient, error)
type encryptSecretFunc func([]byte, string, string, *ecdsa.PublicKey) (string, string, error)
type parseSignerFunc func(string) (*ecdsa.PublicKey, error)

type dependencies struct {
	lookupEnv   func(string) (string, bool)
	newClient   clientFactory
	parseSigner parseSignerFunc
	encrypt     encryptSecretFunc
}

type rootOptions struct {
	environment string
}

func productionDependencies(lookupEnv func(string) (string, bool)) dependencies {
	return dependencies{
		lookupEnv: lookupEnv,
		newClient: func(privateKey, baseURL string) (secretsClient, error) {
			stamper, err := turnkeyapi.NewAPIKeyStamper(privateKey)
			if err != nil {
				return nil, err
			}
			return turnkeyapi.NewClient(baseURL, stamper)
		},
		parseSigner: secretcrypto.ParseSignerPublicKey,
		encrypt:     secretcrypto.EncryptSecret,
	}
}

func Execute(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	lookupEnv func(string) (string, bool),
) int {
	return executeWithDependencies(ctx, args, stdin, stdout, stderr, productionDependencies(lookupEnv))
}

func executeWithDependencies(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	deps dependencies,
) int {
	root := newRootCommand(deps)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		var classified *appError
		if !errors.As(err, &classified) {
			err = payloadError("invalid command or arguments", err)
		}
		return writeError(stderr, err)
	}
	return 0
}

func newRootCommand(deps dependencies) *cobra.Command {
	options := rootOptions{}
	root := &cobra.Command{
		Use:           "secretctl",
		Short:         "Create and list secrets in Turnkey Secret Storage",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if _, err := profileForEnvironment(options.environment); err != nil {
				return environmentFlagError(err)
			}
			return nil
		},
	}
	root.PersistentFlags().StringVar(
		&options.environment,
		"env",
		defaultEnvironment,
		"Turnkey environment: dev, preprod, or prod",
	)
	root.AddCommand(newCreateCommand(deps, &options), newListCommand(deps, &options))
	return root
}

func loadConfiguration(deps dependencies, environment string) (secretsClient, *ecdsa.PublicKey, error) {
	profile, err := profileForEnvironment(environment)
	if err != nil {
		return nil, nil, environmentFlagError(err)
	}
	privateKey, exists := deps.lookupEnv("TURNKEY_API_PRIVATE_KEY")
	if !exists || privateKey == "" {
		return nil, nil, wrapAppError(codeAuthFailed, "TURNKEY_API_PRIVATE_KEY is required", 3, os.ErrNotExist)
	}
	signerKey := nonEmptyEnvironmentOverride(deps, "TURNKEY_SIGNER_PUBLIC_KEY", profile.signerPublicKey)
	parsedSigner, err := deps.parseSigner(signerKey)
	if err != nil {
		return nil, nil, wrapAppError(codeImportFailed, "TURNKEY_SIGNER_PUBLIC_KEY is invalid", 6, err)
	}
	baseURL := nonEmptyEnvironmentOverride(deps, "TURNKEY_API_BASE_URL", profile.apiBaseURL)
	client, err := deps.newClient(privateKey, baseURL)
	if err != nil {
		return nil, nil, wrapAppError(codeAuthFailed, "TURNKEY_API_PRIVATE_KEY is invalid", 3, err)
	}

	return client, parsedSigner, nil
}

func loadListClient(deps dependencies, environment string) (secretsClient, error) {
	profile, err := profileForEnvironment(environment)
	if err != nil {
		return nil, environmentFlagError(err)
	}
	privateKey, exists := deps.lookupEnv("TURNKEY_API_PRIVATE_KEY")
	if !exists || privateKey == "" {
		return nil, wrapAppError(codeAuthFailed, "TURNKEY_API_PRIVATE_KEY is required", 3, os.ErrNotExist)
	}
	baseURL := nonEmptyEnvironmentOverride(deps, "TURNKEY_API_BASE_URL", profile.apiBaseURL)
	client, err := deps.newClient(privateKey, baseURL)
	if err != nil {
		return nil, wrapAppError(codeAuthFailed, "TURNKEY_API_PRIVATE_KEY is invalid", 3, err)
	}
	return client, nil
}
