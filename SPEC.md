Enclave Secret Storage CLI — Specification v0.1 (light)
Shared by Ben Wilson · via Valet · updated 30m ago

Enclave Secret Storage CLI — Specification v0.1 (light)
Status: Draft Audience: Operators and developers who need a simple CLI to populate and browse Turnkey Secret Storage. Scope: Generic tool, no enclave-terraform coupling.

1. Purpose
Provide a minimal command-line interface to:

Create a secret in Turnkey Secret Storage from local input
List secrets with metadata filters
The CLI MUST never print plaintext secret values and MUST store secrets only in Turnkey Secret Storage (not on disk).

2. Non-goals (v0.1)
Delete or update existing secrets
Export/decrypt secrets
Enclave runtime integration
Policy management UX
Rotation workflows (can be done by creating a new secret)
3. Commands
3.1 create
Create a new Secret Storage entry by encrypting a local JSON payload and importing it.

Usage:


secretctl [--env dev|preprod|prod] create \
  [--org-id ORG_ID] \
  [--name NAME] \
  [--property key=value ...] \
  [--allow-empty-values] \
  (--from-env KEY[,KEY...] | --from-file path.json | --stdin)
--env: Turnkey environment; defaults to prod and selects the built-in API base
URL and signer public key
--org-id: Turnkey organization ID; required unless TURNKEY_ORGANIZATION_ID is set
--name: human-readable unique name (recommended format: product/env/logical-name/version)
--property: immutable static properties (repeatable: --property app=enclave, etc.)
Exactly one input source is required:
--from-env: comma-separated env var keys; CLI builds { KEY: $KEY, ... }
--from-file: path to JSON object file
--stdin: read JSON object from standard input
--allow-empty-values: allow present-but-empty environment values and JSON
null, empty strings, empty arrays, or empty objects; without this flag empty
JSON values are rejected recursively
Behavior:

Validates input is a JSON object
Calls InitImportSecrets(num=1)
Requires trusted signer verification material and verifies the server target message
HPKE-encrypts the JSON payload to the ingress target
Calls ImportSecrets
Prints a non-secret result line
Example:


secretctl create \
  --org-id org_example123 \
  --name infra/prod/aws-credentials/2026-08-23 \
  --property app=generic-secretctl \
  --property kind=aws-credentials \
  --property environment=prod \
  --from-env AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN
Output (JSON by default):


{
  "ok": true,
  "secret_id": "secret_abc123",
  "name": "infra/prod/aws-credentials/2026-08-23",
  "static_properties": {
    "app": "generic-secretctl",
    "kind": "aws-credentials",
    "environment": "prod"
  }
}
3.2 list
List existing secrets (metadata only).

Usage:


secretctl [--env dev|preprod|prod] list \
  [--org-id ORG_ID] \
  [--property key=value ...] \
  [--limit N] \
  [--format table|json]
Filters by exact static-property equality when --property is supplied (repeatable)
Returns only metadata: secret_id, name, created_at_unix_ms, static_properties
Default format is table; json returns an array of objects
Example (table):


secretctl list --org-id org_example123 --property kind=aws-credentials --format table
Example (json):


secretctl list --org-id org_example123 --property environment=prod --format json
4. Static properties
Static properties are immutable labels attached to a secret at import time. They enable:

Policy: allow/deny export by labels
Discovery: filter in list by labels
Classification: describe secret kind and ownership
Guidelines:

Include durable identity fields (examples):
app: tool or owning system (e.g., generic-secretctl)
project: optional owner/project tag
environment: dev|staging|prod
kind: secret classification (aws-credentials, cloudflare-token, etc.)
logical_name: stable human label (e.g., aws-prod)
version: optional human-readable version or timestamp
Do not encode mutable state such as active=true or latest=true
5. Safety rules
The CLI MUST NOT print plaintext secret values in normal output or logs
The CLI MUST redact values in error messages
The CLI MUST NOT write plaintext secrets to disk
The CLI SHOULD accept JSON only for payloads in v0.1
The CLI MUST reject missing environment variables. It MUST also reject empty
environment values and JSON null, empty string, empty array, or empty object
values unless --allow-empty-values is supplied.
6. Outputs and exit codes
All commands return exit code 0 on success, non-zero on error.

Common error codes (strings in JSON, mapped to non-zero exit):

AUTH_FAILED: credentials invalid
FEATURE_DISABLED: Secret Storage not enabled for org
PAYLOAD_INVALID: input not valid JSON object or missing required env vars
NAME_CONFLICT: name collides where uniqueness is enforced
IMPORT_FAILED: import activity failed
LIST_FAILED: list query failed
7. Implementation notes
Endpoints used: InitImportSecrets, ImportSecrets, ListSecrets
Use HPKE P-256 transport per ENCLAVE_ENCRYPT_V1
Prefer the official Turnkey client libraries for request signing and activity submission
created_at_unix_ms is the canonical timestamp for display and sorting
Output times SHOULD be shown in human-readable form in table format while preserving raw epoch in json

TURNKEY_API_PRIVATE_KEY is required. The --env flag accepts dev, preprod, or
prod, defaults to prod, and selects built-in TURNKEY_API_BASE_URL and
TURNKEY_SIGNER_PUBLIC_KEY values for that environment. Non-empty values supplied
through TURNKEY_API_BASE_URL or TURNKEY_SIGNER_PUBLIC_KEY override the selected
profile. The signer key is a hex-encoded, 65-byte uncompressed P-256
verification key. TURNKEY_ORGANIZATION_ID supplies --org-id when the flag is
omitted; an explicitly supplied flag takes precedence. Create MUST fail closed
when target verification fails.
8. Examples
Create from file:


secretctl create \
  --org-id org_example123 \
  --name ops/prod/cloudflare-token/2026-08-23 \
  --property kind=cloudflare-token \
  --from-file ./cloudflare.json
List by kind and environment (table):


secretctl list --org-id org_example123 --property kind=cloudflare-token --property environment=prod --format table
9. Roadmap (informative)
export command for strong verification (never prints plaintext by default)
rotate helper that wraps create with naming conventions
delete when Secret Storage supports deletion
Rich JSON Schema validation of payloads
