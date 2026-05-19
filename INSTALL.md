# Installation — tds-auth-api

> Part of the Tracht Digital Solutions multi-repo project.
> tds-auth-api is the **JWT issuer + JWKS publisher**. Customers and
> admins log in here; every other API (`tds-customer-api`,
> `tds-content-api`) verifies their bearer tokens against the JWKS
> this service publishes at `/.well-known/jwks.json`.
>
> This is the **first API to bring up** because the others won't work
> without its `AUTH_API_URL` reachable.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| PHP | 8.3+ with `openssl`, `pdo_mysql`, `fileinfo` | Runtime |
| Composer | 2.x | Dependency management |
| MariaDB | 11.x (or MySQL 8) | `tds_auth` database |
| OpenSSL CLI | any | RSA keypair generation |
| Docker | optional | Local MariaDB without installing one |
| netcup Webhosting | 8000+ | Production target |

## 1. Clone + install

```bash
git clone https://github.com/Tracht-Digital-Solutions/tds-auth-api.git
cd tds-auth-api
composer install
```

## 2. Local MariaDB (via Docker)

```bash
docker run --rm -d \
  --name tds-auth-maria \
  -e MARIADB_ROOT_PASSWORD=dev \
  -e MARIADB_DATABASE=tds_auth_local \
  -p 3307:3306 \
  mariadb:11
```

Port `3307` (not the default 3306) leaves room for the other APIs
to bring up their own MariaDB containers in parallel without
clashing. The credential map ends up like this when all four APIs
run locally:

| API | Port | DB name |
|---|---|---|
| tds-auth-api | 3307 | tds_auth_local |
| tds-content-api | 3308 | tds_content_local |
| tds-contact-api | 3309 | tds_contact_local |
| tds-customer-api | 3310 | tds_customer_local |

## 3. Generate the JWT keypair

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

The private key signs JWTs; the public key is published as the JWKS
endpoint that other APIs verify against. **Never commit
`keys/private.pem`** — it's already in `.gitignore`.

## 4. Configure

```bash
cp .env.example .env
```

Fill in:

```ini
APP_ENV=local
DB_HOST=127.0.0.1
DB_PORT=3307
DB_NAME=tds_auth_local
DB_USER=root
DB_PASS=dev

# Multi-line PEM. Either embed literal newlines or use \n escapes —
# the bootstrap reads both via the standard env-loader.
JWT_PRIVATE_KEY="$(cat keys/private.pem)"

# Strong random 32+ char string. Same value as tds-content-api's
# ADMIN_TOKEN and tds-customer-api's ADMIN_TOKEN — the three share
# the secret.
ADMIN_TOKEN=$(openssl rand -hex 32)

# Comma-separated frontend origins
CORS_ALLOWED_ORIGINS=http://localhost:4321,https://admin.tracht-digital.de,https://app.tracht-digital.de
```

## 5. Migrate + run

```bash
composer migrate
composer start         # http://localhost:8001
```

## 6. Verify

```bash
# Liveness
curl -i http://localhost:8001/healthz
# 200 OK with DB status

# JWKS endpoint must work — every other API depends on this
curl -s http://localhost:8001/.well-known/jwks.json | jq

# Admin login (after setting ADMIN_TOKEN)
curl -sX POST http://localhost:8001/admin/login \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\"}" -i
# 200 OK with JWT in body + Set-Cookie
```

## 7. Production deployment (manual)

Auto-deploy was removed; deploy by hand to netcup:

```bash
# 1. Install no-dev deps locally
composer install --no-dev --optimize-autoloader

# 2. SFTP the project tree (excluding .env, var/, keys/private.pem)
#    to ~/sites/api.tracht-digital.de/auth/releases/<TIMESTAMP>/

# 3. Drop the deploy marker
touch dist/.deploy-complete
# (well, technically: SFTP an empty .deploy-complete file into the
#  release dir. install.php checks for its presence.)

# 4. Trigger install.php to activate the release + run migrations
curl --fail \
  "https://api.tracht-digital.de/install.php?action=install-php\
&target=auth&release=<TIMESTAMP>&migrate=1&token=<INSTALL_TOKEN>"
```

The shared `~/sites/api.tracht-digital.de/auth/shared/.env` on
netcup carries the production secrets. It's symlinked into each
release. **`JWT_PRIVATE_KEY` lives in that .env only** — never SFTP
the local `keys/private.pem`.

## Related repos

- [tds-shared](https://github.com/Tracht-Digital-Solutions/tds-shared) — type definitions for login payloads
- [tds-customer-api](https://github.com/Tracht-Digital-Solutions/tds-customer-api) — verifies JWTs against this JWKS, calls back via `POST /admin/customer-credentials`
- [tds-content-api](https://github.com/Tracht-Digital-Solutions/tds-content-api) — (Phase 4) will swap from `ADMIN_TOKEN` Bearer to JWKS-verified admin JWTs
- [tds-admin](https://github.com/Tracht-Digital-Solutions/tds-admin) — (Phase 4) will get its admin cookie from this API
- [tds-customer](https://github.com/Tracht-Digital-Solutions/tds-customer) — gets the customer cookie from this API

## Troubleshooting

**JWKS endpoint returns empty array.**
The migration didn't run, or `JWT_PRIVATE_KEY` is unset / malformed.
Tail PHP error log; the bootstrap fails fast with a `RuntimeException`
if the key can't parse.

**Downstream API returns `Invalid token: Key set not found`.**
The other API can't reach this one's JWKS endpoint. Check
`AUTH_API_URL` on the downstream + that the URL is reachable from
its host.

**`composer migrate` errors on FK constraint.**
The DB existed before with a different schema. Drop + recreate:
`docker exec -it tds-auth-maria mariadb -uroot -pdev -e 'DROP DATABASE tds_auth_local; CREATE DATABASE tds_auth_local;'`
then re-run `composer migrate`.
