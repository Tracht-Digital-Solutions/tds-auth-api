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
| Production host | shared Apache/PHP | Deploy target |

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
CORS_ALLOWED_ORIGINS=http://localhost:4321,https://management.tracht-digital.de,https://app.tracht-digital.de
```

## 5. Migrate + run

```bash
composer migrate
composer start         # http://localhost:8003
```

### Setup (bootstrap) admin

The `20260701000002_seed_bootstrap_admin` migration seeds **one** admin so a
freshly-migrated stack can be logged into without SSH — then forces you to
secure it. It runs **only when no admin exists yet** (idempotent; skips an
established install or a taken email), and the seeded row carries
`must_change_password = 1`, so the default credential is useless until you set
your own password.

| | Default | Override (host `.env`, set **before** the first migrate) |
|---|---|---|
| Email | `admin@tracht-digital.de` | `ADMIN_BOOTSTRAP_EMAIL` |
| Password | `tds-setup-admin` | `ADMIN_BOOTSTRAP_PASSWORD` |

> Set `ADMIN_BOOTSTRAP_EMAIL` / `ADMIN_BOOTSTRAP_PASSWORD` in the host
> `services/auth/.env` **before** the first migrate so the public default never
> exists. On production the auth migrations run automatically via the gateway on
> the first request after deploy (`tds-gateway-api`), so set these first.

**First login → forced password change**
1. `POST /login` `{"email","password"}` → token + `"mustChangePassword": true`.
2. `PUT /password` `{"old":"…","new":"…"}` (new ≥ 12 chars, must differ) — sets a
   real password and clears the forced-change flag. The admin frontend shows this as
   the automatic "change your password" screen on first login.

**More admins / recovery:** `composer create-admin -- you@example.com [password]`
(promotes an existing user or creates one; generates a strong password if none
is given). See `AGENTS.md` → *Bootstrapping the first admin* for detail.

## 6. Verify

```bash
# Liveness
curl -i http://localhost:8003/healthz
# 200 OK with DB status

# JWKS endpoint must work — every other API depends on this
curl -s http://localhost:8003/.well-known/jwks.json | jq

# Admin login (after setting ADMIN_TOKEN)
curl -sX POST http://localhost:8003/admin/login \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\"}" -i
# 200 OK with JWT in body + Set-Cookie
```

## 7. Tests

Pure unit tests cover the JWT issue/verify round-trip, RS256 signing,
cookie-factory output, the admin/refresh/JWKS actions, the
`AdminAuthMiddleware`, and the customer/admin login flows that don't
need a database. They generate a fresh RSA keypair per test run so no
secrets leak into the suite:

```bash
composer test
```

The following are **integration tests** that exercise real MariaDB —
`PdoSessionRepositoryTest`, `Customer\LoginActionTest`,
`Admin\CreateCustomerCredentialActionTest`. Without `TDS_TEST_DB_DSN`
set they skip cleanly.

Spin up a throwaway test DB (port `3399` so it doesn't clash with the
four per-repo dev DBs):

```bash
docker run --rm -d \
  --name tds-test-maria \
  -e MARIADB_ROOT_PASSWORD=test \
  -e MARIADB_DATABASE=tds_test \
  -p 3399:3306 \
  mariadb:11
```

Export the connection and re-run the suite:

```bash
export TDS_TEST_DB_DSN="mysql:host=127.0.0.1;port=3399;dbname=tds_test;charset=utf8mb4"
export TDS_TEST_DB_USER=root
export TDS_TEST_DB_PASS=test
composer test
```

The integration tests drop + recreate the tables they touch on every
run, so no `composer migrate` against the test DB is needed. The same
container can be reused by every TDS API's test suite — just don't run
two of them in parallel against it (the schemas overlap).

## 8. Production deployment

In production this API does **not** run on its own — it ships inside the
**`tds-gateway-api` bundle** as `services/auth/` and is served by the gateway in
its default **in-process** mode (`GATEWAY_MODE=inprocess`): one PHP-FPM app for
the whole API surface, **no per-service `php -S` process to start**. The full
release recipe (Plesk Git checkout of the gateway's `release` branch, docroot on
`gateway/public`, DBs, migrations, `.env`s — most of it via the `/install.php`
wizard) lives in the gateway repo's **`DEPLOY-PLESK.md`**.

This service's config lives at `services/auth/.env` on the host (untracked,
survives deploys). **`JWT_PRIVATE_KEY` lives there only** (or as
`services/auth/keys/private.pem`, mode 600) — it is never committed to the repo.
A manual *Actions → Release* on this repo dispatches a gateway re-assemble +
deploy; pushes to `main` only build the (undeployed) `dev` bundle.

## Related repos

- [tds-shared-pkg](https://github.com/Tracht-Digital-Solutions/tds-shared-pkg) — type definitions for login payloads
- [tds-customer-api](https://github.com/Tracht-Digital-Solutions/tds-customer-api) — verifies JWTs against this JWKS, calls back via `POST /admin/customer-credentials`
- [tds-content-api](https://github.com/Tracht-Digital-Solutions/tds-content-api) — verifies admin write JWTs against this API's JWKS
- [tds-admin](https://github.com/Tracht-Digital-Solutions/tds-admin) — gets its admin session cookie from this API's `/login`
- [tds-customer-legacy-frontend](https://github.com/Tracht-Digital-Solutions/tds-customer-legacy-frontend) — gets the customer cookie from this API

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

**`composer test` fails with `Cannot find PHPUnit`.**
You installed with `--no-dev`. Re-run plain `composer install` to
pull `phpunit/phpunit` from `require-dev`.

**`composer test` fails generating an RSA keypair.**
The `openssl` PHP extension is missing or the system OpenSSL is too
old. `php -m | grep openssl` should list it. On Debian-derived:
`sudo apt install php8.3-openssl`.
