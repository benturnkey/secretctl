package turnkeyapi

import (
	"fmt"

	"github.com/tkhq/go-sdk/pkg/apikey"
)

type APIKeyStamper struct {
	key *apikey.Key
}

func NewAPIKeyStamper(privateKey string) (*APIKeyStamper, error) {
	key, err := apikey.FromTurnkeyPrivateKey(privateKey, apikey.SchemeP256)
	if err != nil {
		return nil, fmt.Errorf("parse Turnkey API private key: %w", err)
	}

	return &APIKeyStamper{key: key}, nil
}

func (s *APIKeyStamper) Stamp(body []byte) (string, error) {
	stamp, err := apikey.Stamp(body, s.key)
	if err != nil {
		return "", fmt.Errorf("create Turnkey API stamp: %w", err)
	}

	return stamp, nil
}
