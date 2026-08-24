package command

import (
	"errors"
	"fmt"

	"github.com/tkhq/go-sdk/pkg/encryptionkey"
)

const (
	defaultEnvironment = "prod"

	devAPIBaseURL     = "https://api.dev.turnkey.engineering"
	preprodAPIBaseURL = "https://api.preprod.turnkey.engineering"
	prodAPIBaseURL    = "https://api.turnkey.com"

	devSignerPublicKey     = "048cf9ed5f579298cc1571823a3222b82d80c529c551f6070fbe712ae1a9e8d1a23b7006e306d27190358dfcd9c44624918a00f23c920a33cb14f5b026eafc865d"
	preprodSignerPublicKey = "04f3422b8afbe425d6ece77b8d2469954715a2ff273ab7ac89f1ed70e0a9325eaa1698b4351fd1b23734e65c0b6a86b62dd49d70b37c94606aac402cbd84353212"
	prodSignerPublicKey    = encryptionkey.SignerProductionPublicKey
)

type environmentProfile struct {
	apiBaseURL      string
	signerPublicKey string
}

func profileForEnvironment(name string) (environmentProfile, error) {
	switch name {
	case "dev":
		return environmentProfile{
			apiBaseURL:      devAPIBaseURL,
			signerPublicKey: devSignerPublicKey,
		}, nil
	case "preprod":
		return environmentProfile{
			apiBaseURL:      preprodAPIBaseURL,
			signerPublicKey: preprodSignerPublicKey,
		}, nil
	case "prod":
		return environmentProfile{
			apiBaseURL:      prodAPIBaseURL,
			signerPublicKey: prodSignerPublicKey,
		}, nil
	default:
		return environmentProfile{}, fmt.Errorf("unsupported environment %q", name)
	}
}

func environmentFlagError(err error) error {
	return payloadError("--env must be dev, preprod, or prod", err)
}

func resolveOrganizationID(flagValue string, flagChanged bool, deps dependencies) (string, error) {
	if flagChanged {
		if flagValue == "" {
			return "", payloadError("--org-id must not be empty", errors.New("empty organization ID"))
		}
		return flagValue, nil
	}

	organizationID, exists := deps.lookupEnv("TURNKEY_ORGANIZATION_ID")
	if !exists || organizationID == "" {
		return "", payloadError(
			"--org-id or TURNKEY_ORGANIZATION_ID is required",
			errors.New("missing organization ID"),
		)
	}
	return organizationID, nil
}

func nonEmptyEnvironmentOverride(deps dependencies, name, fallback string) string {
	value, exists := deps.lookupEnv(name)
	if !exists || value == "" {
		return fallback
	}
	return value
}
