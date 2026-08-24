package secretcrypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
)

const maxEncryptedPayloadBytes = 124 * 1024

func ParseSignerPublicKey(encoded string) (*ecdsa.PublicKey, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signer public key: %w", err)
	}
	publicKey, err := enclave_encrypt.ToEcdsaPublic(decoded)
	if err != nil {
		return nil, fmt.Errorf("parse signer public key: %w", err)
	}

	return publicKey, nil
}

func EncryptSecret(
	plaintext []byte,
	targetMessage string,
	organizationID string,
	signerPublicKey *ecdsa.PublicKey,
) (secretPayload string, targetPublicKey string, err error) {
	if signerPublicKey == nil {
		return "", "", errors.New("signer public key is required")
	}

	var message enclave_encrypt.ServerTargetMsgV1
	if err := json.Unmarshal([]byte(targetMessage), &message); err != nil {
		return "", "", fmt.Errorf("decode enclave target message: %w", err)
	}
	if message.Version != enclave_encrypt.DataVersion {
		return "", "", fmt.Errorf("unsupported enclave target message version %q", message.Version)
	}

	var targetData enclave_encrypt.ServerTargetData
	if err := json.Unmarshal(message.Data, &targetData); err != nil {
		return "", "", fmt.Errorf("decode signed enclave target data: %w", err)
	}
	if targetData.OrganizationId != organizationID {
		return "", "", errors.New("enclave target organization does not match requested organization")
	}
	if targetData.UserId != "" {
		return "", "", errors.New("enclave target is not a secret ingress target")
	}
	if len(targetData.TargetPublic) == 0 {
		return "", "", errors.New("enclave target message has no target public key")
	}

	client, err := enclave_encrypt.NewEnclaveEncryptClient(signerPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("create enclave encryption client: %w", err)
	}
	encrypted, err := client.Encrypt(
		enclave_encrypt.Bytes(plaintext),
		enclave_encrypt.Bytes(targetMessage),
		organizationID,
		"",
	)
	if err != nil {
		return "", "", fmt.Errorf("verify target and encrypt secret: %w", err)
	}

	payload, err := json.Marshal(encrypted)
	if err != nil {
		return "", "", fmt.Errorf("encode encrypted secret: %w", err)
	}
	if len(payload) > maxEncryptedPayloadBytes {
		return "", "", errors.New("encrypted secret exceeds Turnkey payload limit")
	}

	return string(payload), hex.EncodeToString(targetData.TargetPublic), nil
}
