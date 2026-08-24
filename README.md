# secretctl

`secretctl` creates and lists metadata for encrypted secrets in Turnkey Secret
Storage. It never exports secrets and does not write plaintext secret values to
disk.

> [!IMPORTANT]
> Turnkey Secret Storage must be enabled for the organization before using this
> CLI. Turnkey operators can enable it with the `FEATURE_FLAG_SECRETS_API` feature
> flag.
>

## Development

The repository flake provides all build and test tools:

```sh
nix develop
go test ./...
go vet ./...
go build ./cmd/secretctl
```

Build or run without entering the shell:

```sh
nix build path:.
nix run path:. -- --help
```

## Configuration

Select the Turnkey environment with the persistent `--env` flag. It accepts
`dev`, `preprod`, or `prod` and defaults to `prod`:

```sh
secretctl --env preprod list
```

Each environment provides built-in API and signer configuration:

| Environment | API base URL |
| --- | --- |
| `dev` | `https://api.dev.turnkey.engineering` |
| `preprod` | `https://api.preprod.turnkey.engineering` |
| `prod` | `https://api.turnkey.com` |

The corresponding trusted signer public keys are pinned in
[`internal/command/environment.go`](internal/command/environment.go).

Set credentials and optional overrides in the process environment:

- `TURNKEY_API_PRIVATE_KEY` is the Turnkey P-256 API private key.
- `TURNKEY_ORGANIZATION_ID` supplies the organization ID when `--org-id` is
  omitted. An explicitly provided `--org-id` takes precedence.
- A non-empty `TURNKEY_SIGNER_PUBLIC_KEY` overrides the selected environment's
  trusted signer key. It must be a 65-byte, uncompressed P-256 verification key
  encoded as hex. `create` fails closed if the returned ingress target is not
  signed by this key.
- A non-empty `TURNKEY_API_BASE_URL` overrides the selected environment's API
  base URL.

The CLI does not read configuration or credentials from files.

## Create

Exactly one input source is required:

```sh
secretctl create \
  --org-id org_example123 \
  --name infra/prod/aws-credentials/2026-08-23 \
  --property kind=aws-credentials \
  --property environment=prod \
  --from-env AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN
```

`--org-id` may be omitted when `TURNKEY_ORGANIZATION_ID` is set.

`--from-file PATH` and `--stdin` accept one JSON object. Empty environment
values and JSON `null`, `""`, `[]`, or `{}` values are rejected recursively by
default. Pass `--allow-empty-values` to permit them. Missing environment
variables are always errors.

Create output is JSON and contains only the new secret ID, optional name, and
static properties. The canonical creation timestamp is available through
`list`, because the import API does not return it.

## List

```sh
secretctl list \
  --org-id org_example123 \
  --property kind=aws-credentials \
  --property environment=prod \
  --limit 10 \
  --format table
```

`--org-id` may be omitted when `TURNKEY_ORGANIZATION_ID` is set.

Repeated properties use exact-match AND semantics. Turnkey does not currently
filter properties server-side, so `secretctl` scans metadata pages until it
finds the requested number of matches. `--format json` preserves
`created_at_unix_ms`; table output displays the timestamp as UTC RFC3339.

Successful data is written to stdout. Structured, sanitized errors are written
to stderr.
