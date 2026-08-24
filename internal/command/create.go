package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	secretinput "github.com/tkhq/secretctl/internal/input"
	"github.com/tkhq/secretctl/internal/property"
	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

type createOptions struct {
	organizationID   string
	name             string
	properties       []string
	fromEnvironment  string
	fromFile         string
	fromStdin        bool
	allowEmptyValues bool
}

func newCreateCommand(deps dependencies, globalOptions *rootOptions) *cobra.Command {
	options := createOptions{}
	command := &cobra.Command{
		Use:   "create",
		Short: "Encrypt and import a JSON secret",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runCreate(command, deps, *globalOptions, options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.organizationID, "org-id", "", "Turnkey organization ID (or TURNKEY_ORGANIZATION_ID)")
	flags.StringVar(&options.name, "name", "", "unique human-readable secret name")
	flags.StringArrayVar(&options.properties, "property", nil, "immutable static property in key=value form")
	flags.StringVar(&options.fromEnvironment, "from-env", "", "comma-separated environment variable names")
	flags.StringVar(&options.fromFile, "from-file", "", "path to a JSON object")
	flags.BoolVar(&options.fromStdin, "stdin", false, "read a JSON object from standard input")
	flags.BoolVar(&options.allowEmptyValues, "allow-empty-values", false, "allow empty strings, arrays, objects, and null values")
	return command
}

func runCreate(command *cobra.Command, deps dependencies, globalOptions rootOptions, options createOptions) error {
	organizationID, err := resolveOrganizationID(
		options.organizationID,
		command.Flags().Changed("org-id"),
		deps,
	)
	if err != nil {
		return err
	}
	if command.Flags().Changed("name") && options.name == "" {
		return payloadError("--name must not be empty", errors.New("empty secret name"))
	}

	sourceCount := 0
	if command.Flags().Changed("from-env") {
		sourceCount++
	}
	if command.Flags().Changed("from-file") {
		sourceCount++
	}
	if options.fromStdin {
		sourceCount++
	}
	if sourceCount != 1 {
		return payloadError("exactly one of --from-env, --from-file, or --stdin is required", errors.New("invalid input source count"))
	}

	staticProperties, err := property.Parse(options.properties)
	if err != nil {
		return payloadError("static properties are invalid", err)
	}
	plaintext, err := loadPlaintext(command, deps, options)
	if err != nil {
		return err
	}
	defer clear(plaintext)

	client, signerPublicKey, err := loadConfiguration(deps, globalOptions.environment)
	if err != nil {
		return err
	}
	initResult, err := client.InitImportSecrets(command.Context(), organizationID)
	if err != nil {
		return operationError("import", err)
	}
	if len(initResult.EnclaveTargetMessages) != 1 {
		return operationError("import", fmt.Errorf("InitImportSecrets returned %d target messages", len(initResult.EnclaveTargetMessages)))
	}

	secretPayload, targetPublicKey, err := deps.encrypt(
		plaintext,
		initResult.EnclaveTargetMessages[0],
		organizationID,
		signerPublicKey,
	)
	if err != nil {
		return operationError("import", err)
	}
	importResult, err := client.ImportSecrets(command.Context(), organizationID, turnkeyapi.ImportSecretParams{
		Name:             optionalString(options.name),
		SecretPayload:    secretPayload,
		TargetPublicKey:  targetPublicKey,
		EncryptionSuite:  turnkeyapi.TransportEncryptionSuiteEnclaveEncryptV1,
		StaticProperties: staticProperties,
	})
	if err != nil {
		return operationError("import", err)
	}
	if len(importResult.SecretIDs) != 1 || importResult.SecretIDs[0] == "" {
		return operationError("import", fmt.Errorf("ImportSecrets returned %d secret IDs", len(importResult.SecretIDs)))
	}

	propertiesOutput := make(map[string]string, len(staticProperties))
	for _, staticProperty := range staticProperties {
		propertiesOutput[staticProperty.Key] = staticProperty.Value
	}
	output := struct {
		OK               bool              `json:"ok"`
		SecretID         string            `json:"secret_id"`
		Name             *string           `json:"name,omitempty"`
		StaticProperties map[string]string `json:"static_properties"`
	}{
		OK:               true,
		SecretID:         importResult.SecretIDs[0],
		Name:             optionalString(options.name),
		StaticProperties: propertiesOutput,
	}
	encoder := json.NewEncoder(command.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return wrapAppError(codeInternal, "could not write command output", 1, err)
	}

	return nil
}

func loadPlaintext(command *cobra.Command, deps dependencies, options createOptions) ([]byte, error) {
	if command.Flags().Changed("from-env") {
		plaintext, err := secretinput.FromEnvironment(options.fromEnvironment, deps.lookupEnv, options.allowEmptyValues)
		if err != nil {
			return nil, payloadError("environment secret input is invalid", err)
		}
		return plaintext, nil
	}
	if options.fromStdin {
		plaintext, err := secretinput.FromJSON(command.InOrStdin(), options.allowEmptyValues)
		if err != nil {
			return nil, payloadError("standard input must contain a valid JSON object", err)
		}
		return plaintext, nil
	}

	file, err := os.Open(options.fromFile)
	if err != nil {
		return nil, payloadError("could not open JSON input file", err)
	}
	plaintext, readErr := secretinput.FromJSON(file, options.allowEmptyValues)
	closeErr := file.Close()
	if readErr != nil {
		return nil, payloadError("JSON input file is invalid", readErr)
	}
	if closeErr != nil {
		return nil, payloadError("could not close JSON input file", closeErr)
	}
	return plaintext, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
