package turnkeyapi

const (
	TransportEncryptionSuiteEnclaveEncryptV1 = "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1"

	activityStatusCreated              = "ACTIVITY_STATUS_CREATED"
	activityStatusPending              = "ACTIVITY_STATUS_PENDING"
	activityStatusCompleted            = "ACTIVITY_STATUS_COMPLETED"
	activityStatusFailed               = "ACTIVITY_STATUS_FAILED"
	activityStatusConsensusNeeded      = "ACTIVITY_STATUS_CONSENSUS_NEEDED"
	activityStatusRejected             = "ACTIVITY_STATUS_REJECTED"
	activityStatusAuthenticatorsNeeded = "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED"
)

type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Pagination struct {
	After *string `json:"after,omitempty"`
	Limit *string `json:"limit,omitempty"`
}

type SecretMetadata struct {
	SecretID         string     `json:"secretId"`
	Name             *string    `json:"name,omitempty"`
	StaticProperties []KeyValue `json:"staticProperties"`
	CreatedAtUnixMs  string     `json:"createdAtUnixMs"`
}

type ListSecretsRequest struct {
	OrganizationID    string      `json:"organizationId"`
	PaginationOptions *Pagination `json:"paginationOptions,omitempty"`
}

type ListSecretsResponse struct {
	Secrets []SecretMetadata `json:"secrets"`
}

type InitImportSecretsResult struct {
	EnclaveTargetMessages []string `json:"enclaveTargetMessages"`
}

type ImportSecretsResult struct {
	SecretIDs []string `json:"secretIds"`
}

type ImportSecretParams struct {
	Name             *string    `json:"name,omitempty"`
	SecretPayload    string     `json:"secretPayload"`
	TargetPublicKey  string     `json:"targetPublicKey"`
	EncryptionSuite  string     `json:"encryptionSuite"`
	StaticProperties []KeyValue `json:"staticProperties,omitempty"`
}

type activityResponse struct {
	Activity activity `json:"activity"`
}

type activity struct {
	ID      string         `json:"id"`
	Status  string         `json:"status"`
	Result  activityResult `json:"result"`
	Failure *rpcStatus     `json:"failure,omitempty"`
}

type activityResult struct {
	InitImportSecretsResult *InitImportSecretsResult `json:"initImportSecretsResult,omitempty"`
	ImportSecretsResult     *ImportSecretsResult     `json:"importSecretsResult,omitempty"`
}

type rpcStatus struct {
	Code    *int    `json:"code,omitempty"`
	Message *string `json:"message,omitempty"`
}

type activityEnvelope[T any] struct {
	Type           string `json:"type"`
	TimestampMs    string `json:"timestampMs"`
	OrganizationID string `json:"organizationId"`
	Parameters     T      `json:"parameters"`
}

type initImportSecretsIntent struct {
	EncryptionSuite string `json:"encryptionSuite"`
	NumSecrets      int    `json:"numSecrets"`
}

type importSecretsIntent struct {
	Secrets []ImportSecretParams `json:"secrets"`
}

type getActivityRequest struct {
	OrganizationID string `json:"organizationId"`
	ActivityID     string `json:"activityId"`
}
