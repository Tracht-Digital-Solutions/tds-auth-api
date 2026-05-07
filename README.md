# tds-auth-api

JWT auth micro-backend. PHP 8.3 + Slim 4 + firebase/php-jwt + RS256.
Deploys to **netcup Webhosting 8000** at
`https://api.tracht-digital.de/auth/`.

Issues admin and customer tokens; other services verify via the
JWKS endpoint without seeing the private key.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/admin/login` | shared `ADMIN_TOKEN` | Issue admin JWT (cookie + body) |
| `DELETE` | `/admin/login` | session | Revoke session + clear cookie |
| `POST` | `/customer/login` | n/a | **Stub** — Phase 8 implements |
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
```

Quick test:

```bash
curl -X POST http://localhost:8003/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"token":"YOUR_ADMIN_TOKEN_FROM_ENV"}' -i
# 200 OK + JWT in body and Set-Cookie
```

## Deploy

Push to `main`. GitHub Actions excludes `keys/private.pem` from the
upload (the private key lives in netcup's `.env` only). Then it
SFTPs the release dir, drops `.deploy-complete`, and hits
`install.php?action=install-php&target=auth&migrate=1`.

## Required GitHub secrets / vars

- `secrets.NETCUP_FTP_HOST` / `NETCUP_FTP_USER` / `NETCUP_FTP_PASSWORD`
- `secrets.INSTALL_TOKEN`
- `vars.INSTALLER_URL`

Plus on netcup (`~/sites/api.tracht-digital.de/auth/shared/.env`):
- `JWT_PRIVATE_KEY` (multi-line PEM, with `\n` escapes if your env
  loader needs single-line)
- `ADMIN_TOKEN` (shared admin secret — strong, 32+ chars)
- DB creds for `tds_auth`
