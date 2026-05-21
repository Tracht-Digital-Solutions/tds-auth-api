# tds-auth-api

> **Setting this up from scratch?** See [`INSTALL.md`](INSTALL.md) for
> the step-by-step bring-up (composer → MariaDB → JWT keypair → env →
> migrate → smoke test → manual deploy). This README documents the
> endpoints, auth model, and runbook for ongoing operation.

---


JWT auth micro-backend. PHP 8.3 + Slim 4 + firebase/php-jwt + RS256.
Deploys to **netcup Webhosting 8000** at
`https://api.tracht-digital.de/auth/`.

Issues admin and customer tokens; other services verify via the
JWKS endpoint without seeing the private key.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/admin/login` | shared `ADMIN_TOKEN` (body) | Issue admin JWT (cookie + body) |
| `DELETE` | `/admin/login` | session | Revoke session + clear cookie |
| `POST` | `/admin/customer-credentials` | Bearer `ADMIN_TOKEN` | Server-to-server: store an argon2id credential for a customer (called by tds-customer-api during onboarding) |
| `POST` | `/customer/login` | n/a | Email + password → customer JWT (cookie + body) |
| `POST` | `/refresh` | session | Rotate access token |
| `GET` | `/.well-known/jwks.json` | none | Publish public key for verification |

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
composer migrate
composer start           # http://localhost:8003
composer test            # run the PHPUnit suite (see INSTALL.md §7)
```

Quick test:

```bash
curl -X POST http://localhost:8003/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"token":"YOUR_ADMIN_TOKEN_FROM_ENV"}' -i
# 200 OK + JWT in body and Set-Cookie
```

## Deploy

Auto-deploy via GitHub Actions was removed. Deploy by hand:

1. `composer install --no-dev --optimize-autoloader`
2. SFTP the project (excluding `keys/private.pem` — the private key
   lives in netcup's `.env` only) to
   `~/sites/api.tracht-digital.de/auth/releases/<TS>/`
3. Drop `.deploy-complete` in the release dir
4. Hit `install.php?action=install-php&target=auth&release=<TS>&migrate=1&token=<INSTALL_TOKEN>`

## Required env on netcup

`~/sites/api.tracht-digital.de/auth/shared/.env`:
- `JWT_PRIVATE_KEY` (multi-line PEM, with `\n` escapes if your env
  loader needs single-line)
- `ADMIN_TOKEN` (shared admin secret — strong, 32+ chars)
- DB creds for `tds_auth`

The five legacy Repository Secrets (`NETCUP_FTP_*`, `INSTALL_TOKEN`)
and the `INSTALLER_URL` variable are unused now and can be cleaned up.
