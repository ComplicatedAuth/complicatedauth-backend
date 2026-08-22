# ComplicatedAuth Backend

Authoritative Go API for Tenant administration and project-scoped authentication.

## Local development

Copy `.env.example` to `.env`, provide a strong `SECRET_HASH_KEY`, start PostgreSQL, then run:

```sh
set -a; source .env; set +a
go run ./cmd/server
```

Migrations run forward automatically at startup. Browser control-plane mutations must carry the exact `CONSOLE_ORIGIN` in their `Origin` or `Referer` header.

### Database change safety

Migration files are append-only public release artifacts. Startup takes a
PostgreSQL advisory lock, verifies the SHA-256 checksum of every applied
`*.up.sql` file, and rejects a release that changed or removed history. Add a
new, six-digit migration for every schema change; never edit an applied file.
The first checksum-aware release seals the exact contents of migration records
created by older versions.

`internal/store.IdempotencyStore` provides the database-backed claim, lease,
request-hash conflict, exact-response replay, and bounded cleanup semantics used
by retry-safe mutations. An operation must hash every result-affecting input,
scope keys to its authenticated principal and operation, and persist the final
HTTP response before acknowledging success. The primitive is internal until an
operation explicitly publishes the `Idempotency-Key` contract in OpenAPI.

Login throttling is also PostgreSQL-backed and shared by every API replica.
Policies keep separate keyed digests for console source IPs, console identities,
Project login starts, and Project password verification; raw emails and IP
addresses are not stored in limiter records. If the limiter is unavailable,
authentication fails closed with `503 dependency_unavailable`.

Forwarding headers are ignored by default. Set `TRUSTED_PROXY_CIDRS` to the exact ingress proxy IPs or CIDRs before relying on `X-Forwarded-For` for throttling and audit source addresses.

### Background jobs

Every API replica runs PostgreSQL-leased workers across the `retention`,
`email`, and `maintenance` queues.
Claims use `FOR UPDATE SKIP LOCKED`; abandoned leases are recoverable, failures
use bounded exponential backoff with jitter, and an exhausted job becomes
`dead_lettered` instead of retrying forever. Configure the worker pool with:

- `BACKGROUND_JOB_WORKERS` — workers per API process, default `2`, maximum `32`;
- `BACKGROUND_JOB_POLL_INTERVAL` — empty-queue poll interval, default `1s`;
- `BACKGROUND_JOB_LEASE_DURATION` — ownership lease, default `30s`, minimum `5s`.

Support Case purge jobs are deduplicated by case. The handler locks and
re-checks the current case status and retention deadline before deletion, so a
job left behind by a reopen cannot delete an active case. A successful purge
deletes the case graph transactionally and retains a content-free system audit
event. Alert on stale `running` and `dead_lettered` rows; retry a dead-lettered
job only after its failure cause is understood.

The deduplicated `maintenance.cleanup` job runs hourly and deletes expired
transient records in bounded 1,000-row batches, including idempotency records,
rate buckets, login attempts, WebAuthn ceremonies, verification/reset proofs,
ended sessions, OAuth requests/codes/tokens, expired invitations,
delivered-email metadata, and old completed jobs. A full batch reschedules
after one minute so cleanup catches up without monopolizing the database.

The queue is intentionally not exposed through customer HTTP endpoints. With
`DATABASE_URL` configured, operators inspect payload-free summaries and replay
only dead-lettered jobs through:

```sh
go run ./cmd/jobctl list --status dead_lettered --limit 100
go run ./cmd/jobctl replay \
  --job 00000000-0000-0000-0000-000000000000 \
  --actor oncall@example.com \
  --reason "dependency restored; incident INC-123"
```

Replay atomically resets the job and appends an immutable
`platform_operator_actions` record. The actor and remediation reason are
required; payloads are never printed.

### Email verification and recovery

Set `EMAIL_SMTP_ADDRESS` and `EMAIL_FROM` to enable asynchronous Tenant Member
verification, password-reset, and invitation delivery. Authenticated production
SMTP additionally uses `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD`, and
`EMAIL_SMTP_STARTTLS=true`; `EMAIL_DELIVERY_TIMEOUT` defaults to `15s`.
Credentials are rejected without STARTTLS. A development SMTP sink may set
`EMAIL_SMTP_STARTTLS=false` and omit credentials.

Recipients and link payloads are encrypted with `DATA_ENCRYPTION_KEYS`; the
one-time verification and reset proofs themselves are persisted only as hashes.
Delivery jobs contain only an opaque delivery UUID. Delivery is at-least-once:
the stable message ID permits correlation, but an ambiguous SMTP disconnect
after DATA may produce a duplicate message containing the same proof.

Verification and reset request endpoints return the same `202` body for known,
unknown, verified, and disabled accounts. Password reset consumes the proof,
revokes every Tenant Member session and server-tracked OAuth access token,
consumes outstanding authorization codes and login attempts, deletes every
management WebAuthn credential, and requires a fresh password-verified login
plus first-credential enrollment. Tenant invitation proofs are delivered
directly to the invitee and are never returned to the administrator.

## Tenant Member management authentication

Signup and invitation acceptance create `bootstrap` HttpOnly sessions. A
bootstrap session may discover itself, sign out, and register the member's
first management WebAuthn credential; ordinary management resources require
`strong` assurance.

Login creates a five-minute, non-enumerating attempt. Its one-time client
secret is returned only on creation, remains in browser function memory, and is
sent only in `X-ComplicatedAuth-Login-Secret` to child operations. Password
verification does not create a session. A user-verified passkey or attested
cross-platform security-key assertion consumes the attempt and creates a
strong session.

Tenant Members may hold at most ten named management credentials. Registration
supplies existing identifiers in `excludeCredentials`, reads expose safe
metadata only, and rename/removal require the current strong ETag. The final
credential cannot be deleted; removing another credential revokes every other
management session. WebAuthn RP IDs ignore ports, so production management and
customer applications must use distinct stable hostnames.

## Support Case contract

`/v1/support/cases` is one Tenant-owned resource surface with two authorization
views. Owners, administrators, and support members operate the Tenant inbox.
Project service accounts use exact `support_cases.read` and
`support_cases.write` scopes and can see only their Project and public
correspondence. Internal messages and external references are operator-only.

Case, message, attachment, and external-reference creation use explicit
idempotency keys. Case updates require a strong ETag. Sensitive content,
including subjects, diagnostics, message bodies, filenames, attachment bytes,
and external references, is encrypted with field-specific authenticated
context. Attachments are constrained to the documented allowlist and size
limits but remain untrusted input; production operator tooling must scan or
quarantine files before opening them.

## Browser authentication flow

The customer BFF starts a five-minute login attempt with `POST /v1/projects/{project_uid}/runtime/login/start`, then forwards its `login_reference` as `X-ComplicatedAuth-Login` while factors are verified. The browser must never receive the Project service credential or the backend login/session references; `@complicatedauth/server` maps them to separate browser-safe opaque tokens.

Assurance policy:

- every login session requires a verified password plus a passkey, hybrid passkey, attested cross-platform security key, or facial match;
- FIDO assertions require user verification, and security-key credentials must have supplied non-`none` attestation when enrolled;
- passkey enrollment requests no attestation; security-key enrollment requests direct attestation;
- all FIDO enrollments require discoverable credentials and user verification.

Attestation conveyance confirms that an authenticator supplied attestation data; production deployments that need vendor/model trust should additionally validate it against their approved FIDO metadata policy.

## Facial provider adapter

Set `BIOMETRIC_PROVIDER_URL` and optionally `BIOMETRIC_PROVIDER_TOKEN`. The provider contract is:

- `POST /v1/enrollments`: multipart `subject` and `selfie`; returns `{ "template_id": "..." }`.
- `POST /v1/verifications`: multipart `template_id` and `selfie`; returns `{ "matched": true|false }`.
- `DELETE /v1/enrollments/{template_id}`: removes the external template.

Requests include `X-Selfie-Content-Type`; bearer authorization is added when a provider token is configured. ComplicatedAuth stores only the external template ID and discards source bytes after each request. The current single-selfie protocol has no liveness signal and must not be represented as spoof-resistant.
