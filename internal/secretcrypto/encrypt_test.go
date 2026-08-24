package secretcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/tkhq/go-sdk/pkg/enclave_encrypt"
)

func TestEncryptSecretRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	emptyUserID := ""
	server, err := enclave_encrypt.NewEnclaveEncryptServer(privateKey, "org_test", &emptyUserID)
	if err != nil {
		t.Fatalf("create enclave server: %v", err)
	}
	target, err := server.PublishTarget()
	if err != nil {
		t.Fatalf("publish target: %v", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}

	plaintext := []byte(`{"apiKey":"secret"}`)
	payload, targetPublic, err := EncryptSecret(plaintext, string(targetJSON), "org_test", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}
	if targetPublic == "" {
		t.Fatal("target public key is empty")
	}
	var encrypted enclave_encrypt.ClientSendMsg
	if err := json.Unmarshal([]byte(payload), &encrypted); err != nil {
		t.Fatalf("unmarshal encrypted payload: %v", err)
	}
	receiver := server.IntoEnclaveServerRecv()
	decrypted, err := receiver.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if got, want := string(decrypted), string(plaintext); got != want {
		t.Fatalf("decrypted payload = %q, want %q", got, want)
	}
}

func TestEncryptSecretRejectsUntrustedOrMismatchedTargets(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	emptyUserID := ""
	server, err := enclave_encrypt.NewEnclaveEncryptServer(privateKey, "org_test", &emptyUserID)
	if err != nil {
		t.Fatalf("create enclave server: %v", err)
	}
	target, err := server.PublishTarget()
	if err != nil {
		t.Fatalf("publish target: %v", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other signer key: %v", err)
	}
	if _, _, err := EncryptSecret([]byte(`{"key":"value"}`), string(targetJSON), "org_test", &otherKey.PublicKey); err == nil {
		t.Fatal("expected wrong signer key to be rejected")
	}
	if _, _, err := EncryptSecret([]byte(`{"key":"value"}`), string(targetJSON), "org_other", &privateKey.PublicKey); err == nil {
		t.Fatal("expected wrong organization to be rejected")
	}

	target.Version = "v2.0.0"
	unsupportedJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal unsupported target: %v", err)
	}
	if _, _, err := EncryptSecret([]byte(`{"key":"value"}`), string(unsupportedJSON), "org_test", &privateKey.PublicKey); err == nil {
		t.Fatal("expected unsupported version to be rejected")
	}
}

func TestEncryptSecretRejectsNonSecretTarget(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	userID := "user_test"
	server, err := enclave_encrypt.NewEnclaveEncryptServer(privateKey, "org_test", &userID)
	if err != nil {
		t.Fatalf("create enclave server: %v", err)
	}
	target, err := server.PublishTarget()
	if err != nil {
		t.Fatalf("publish target: %v", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}
	if _, _, err := EncryptSecret([]byte(`{"key":"value"}`), string(targetJSON), "org_test", &privateKey.PublicKey); err == nil {
		t.Fatal("expected non-secret target to be rejected")
	}
}

func TestParseSignerPublicKey(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	publicKey, err := privateKey.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert signer public key: %v", err)
	}
	encoded := hex.EncodeToString(publicKey.Bytes())
	parsed, err := ParseSignerPublicKey(encoded)
	if err != nil {
		t.Fatalf("ParseSignerPublicKey() error = %v", err)
	}
	if !parsed.Equal(&privateKey.PublicKey) {
		t.Fatal("parsed signer key does not match")
	}
	if _, err := ParseSignerPublicKey("not-hex"); err == nil {
		t.Fatal("expected invalid signer key to be rejected")
	}
}
