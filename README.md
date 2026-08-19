# ComplicatedAuth Backend

Authoritative Go API for Tenant administration and project-scoped authentication.

## Local development

Copy `.env.example` to `.env`, provide a strong `SECRET_HASH_KEY`, start PostgreSQL, then run:

```sh
set -a; source .env; set +a
go run ./cmd/server
```

Migrations run forward automatically at startup. Browser control-plane mutations must carry the exact `CONSOLE_ORIGIN` in their `Origin` or `Referer` header.

Forwarding headers are ignored by default. Set `TRUSTED_PROXY_CIDRS` to the exact ingress proxy IPs or CIDRs before relying on `X-Forwarded-For` for throttling and audit source addresses.

## Browser authentication flow

The customer BFF starts a five-minute login attempt with `POST /v1/projects/{project_uid}/runtime/login/start`, then forwards its `login_reference` as `X-ComplicatedAuth-Login` while factors are verified. The browser must never receive the Project API key or the backend login/session references; `@complicatedauth/server` maps them to separate browser-safe opaque tokens.

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
