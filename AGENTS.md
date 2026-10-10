# AGENTS.md — tds-auth-api

The **identity service**: PHP 8.3, Slim 4, firebase/php-jwt. It issues and verifies RS256 JWTs;
other backends verify them via `/.well-known/jwks.json` without seeing the private key. Served behind
`tds-gateway-api` at `api.tracht-digital.de/auth/*`. A core dependency of every architecture, never
superseded. It is JSON-only; the login UI is `tds-auth-frontend`.

## Commands

```bash
composer install
composer start                  # php -S localhost:8003 with public/router.php
composer test                   # phpunit; DB tests need TDS_TEST_DB_DSN (+ _USER / _PASS)
composer migrate                # phinx, local env
composer keygen                 # once per environment: keys/private.pem + keys/public.pem
composer create-admin -- you@example.com [password]
```

On Windows, set `OPENSSL_CONF` for the test run (see [docs/agents/testing.md](docs/agents/testing.md)).

## Hard rules

- Record every issued JWT's `jti` in `session`. Never log `JWT_PRIVATE_KEY`; never commit `keys/private.pem`.
- Keep `JWT_TTL_SECONDS` around an hour; "stay signed in" is a refresh, never a longer token.
- Every path that hands out a membership goes through `PermissionResolver::effective()`.
- `Permissions::sanitize()` runs on write only; never filter permissions on read.
- Company-scoped routes are scoped by path and obey every `CompanyUserGuard` rule.
- Existence-revealing routes answer 404, not 403.
- Primary-key columns carry `'null' => false`; when renaming a column, grep the repositories in the same change.
- Env helpers use explicit `?? false`; `CorsMiddleware` goes after `addRoutingMiddleware()`; `php -S` uses `public/router.php`.

## Topic files

| File | Read before |
|---|---|
| [docs/agents/user-model.md](docs/agents/user-model.md) | Changing users, companies, permissions, groups, ceilings or company admins |
| [docs/agents/endpoints.md](docs/agents/endpoints.md) | Adding or changing a route, the avatar, or admin bootstrap |
| [docs/agents/sessions-and-keys.md](docs/agents/sessions-and-keys.md) | Touching JWTs, sessions, refresh, remember-me, passkeys, keys or CORS |
| [docs/agents/database.md](docs/agents/database.md) | Writing a migration, renaming a column or handling time |
| [docs/agents/pitfalls.md](docs/agents/pitfalls.md) | Any change; traps that hit all APIs |
| [docs/agents/testing.md](docs/agents/testing.md) | Writing or running tests |

Operations: [RUNBOOK.md](RUNBOOK.md), [INSTALL.md](INSTALL.md), [README.md](README.md).
Workspace rules: `../CLAUDE.md`. Cross-repo state: `../MIGRATION-STATUS.md`.
