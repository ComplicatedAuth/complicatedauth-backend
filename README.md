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
