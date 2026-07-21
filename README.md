# tds-auth-api

> **Setting this up from scratch?** See [`INSTALL.md`](INSTALL.md) for
> the step-by-step bring-up (composer → MariaDB → JWT keypair → env →
> migrate → smoke test → auto-deploy). This README documents the
> endpoints, auth model, and runbook for ongoing operation.

---


JWT auth micro-backend. PHP 8.3 + Slim 4 + firebase/php-jwt + RS256.
Deploys to **the production host** at
`https://api.tracht-digital.de/auth/`.

Issues admin and customer tokens; other services verify via the
JWKS endpoint without seeing the private key.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/login` | email + password | Unified login (admin + customer) → RS256 JWT (cookie + body). `/customer/login` is a back-compat alias |
| `DELETE` | `/logout` | session | Revoke session + clear cookie. `/admin/login` is a back-compat alias |
| `GET` | `/me` | session | Current principal (id, email, isAdmin, permissions) |
| `PUT` | `/password` | session | Change password (drives the forced first-login change) |
| `POST` | `/admin/customer-credentials` | Bearer `SERVICE_TOKEN`/`ADMIN_TOKEN` | Server-to-server: store an argon2id credential for a customer (called by tds-customer-api during onboarding) |
| `POST` | `/refresh` | session | Rotate access token |
| `GET` | `/.well-known/jwks.json` | none | Publish public key for verification |

Admin write endpoints (`/admin/users`, `/admin/sessions`, …) are gated by a
per-admin JWT (`admin=true`); the shared `ADMIN_TOKEN` Bearer survives only for
the server-to-server call above (as `SERVICE_TOKEN`).

JWT claims:

```json
{
  "iss": "https://api.tracht-digital.de/auth",
  "sub": "admin" | "<customer_id>",
  "aud": "tds-services",
  "iat": 1700000000,
  "exp": 1700003600,
  "jti": "uuid-v4",
  "admin": true,
  "customer_id": null | 42
}
```

## Local dev

```bash
composer install
composer keygen          # writes keys/{private,public}.pem
cp .env.example .env     # paste private key contents into JWT_PRIVATE_KEY
composer migrate         # local dev only — prod is auto-migrated (see below)
composer start           # http://localhost:8003
composer test            # run the PHPUnit suite (see INSTALL.md §7)
```

**On production, migrations apply automatically.** This service is served
in-process by the `tds-gateway-api` bundle, which runs each service's pending
Phinx migrations on the first request after a deploy (in-process, no `proc_open`;
see the gateway's `AGENTS.md` → *Auto-migration*). `/healthz` reports the schema
state in its `db` field — `ok` (migrated), `no-schema` (reachable but tables
missing), or `down` (unreachable); the gateway aggregate goes `503` on the
latter two.

**Setup (bootstrap) admin.** The migrations seed one admin so a fresh install
can be logged into without SSH — default `admin@tracht-digital.de` /
`tds-setup-admin`, flagged `must_change_password` so you're forced to set a real
password on first login. Seeded only when no admin exists; override the default
with `ADMIN_BOOTSTRAP_EMAIL` / `ADMIN_BOOTSTRAP_PASSWORD` **before** the first
migrate. Add more admins with `composer create-admin -- email [password]`. Full
details in `INSTALL.md` §5 and `AGENTS.md`.

Quick test:

```bash
curl -X POST http://localhost:8003/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"token":"YOUR_ADMIN_TOKEN_FROM_ENV"}' -i
# 200 OK + JWT in body and Set-Cookie
```

## Deploy

Deployment is automatic. On a push to `main`, once CI passes, the
`deploy` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
POST-pings the deploy webhook and the production host pulls the new
release and activates it. The signing key never leaves the host's
`.env` (see below) — it is not in the repo.

**Required secret:** set `DEPLOY_WEBHOOK_URL` (repository secret) to the
host's deploy-hook URL — the deploy token is carried inside the URL. If
it isn't set, the deploy ping is skipped (CI still runs).

## Required env on the production host

`~/sites/api.tracht-digital.de/auth/shared/.env`:
- `JWT_PRIVATE_KEY` (multi-line PEM, with `\n` escapes if your env
  loader needs single-line)
- `ADMIN_TOKEN` (shared admin secret — strong, 32+ chars)
- DB creds for `tds_auth`

The only deploy secret now is `DEPLOY_WEBHOOK_URL`. The old `FTP_*` /
`INSTALL_TOKEN` Repository Secrets and the `INSTALLER_URL` variable are
unused and can be cleaned up.
