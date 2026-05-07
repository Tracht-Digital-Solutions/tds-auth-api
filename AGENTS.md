# Agent notes — tds-auth-api

PHP 8.3 + Slim 4 + firebase/php-jwt. Issues and verifies RS256
JWTs. Other backends verify them via `/.well-known/jwks.json`
without ever seeing the private key.

## Endpoints

- `POST /admin/login` — Phase-2 bridge: shared ADMIN_TOKEN → JWT.
- `DELETE /admin/login` — revoke session + clear cookie.
- `POST /customer/login` — STUB until Phase 8.
- `POST /refresh` — rotate access token (verifies signature + checks
  session revocation).
- `GET /.well-known/jwks.json` — public key in JWKS format.

## Key generation

Run once per environment:

```bash
composer keygen
```

Writes `keys/private.pem` (mode 600) and `keys/public.pem`. Copy the
private key contents into `.env` as `JWT_PRIVATE_KEY=` (single line,
literal `\n` escapes if needed). Public key is committed to the repo
so the JWKS endpoint can serve it.

**Don't ever commit `keys/private.pem`.** The .gitignore covers it,
the deploy workflow excludes it from the upload, but the convention
is: private key only ever exists in (a) your password manager, (b)
the netcup `.env`, (c) optionally `keys/private.pem` on the dev
machine. After step (a), feel free to `rm` the file.

## Mental model

- `JwtService` issues + verifies with the loaded keys.
- `SessionRepository` records every issued JWT's `jti` for revocation
  on logout. JWKS verification alone won't catch a logged-out token —
  the consumer would need to call us to check, which we don't do
  yet. For now, logout works inside the auth domain (refresh stops
  working), and other services accept tokens until natural expiry.
- `CookieFactory` builds `Domain=.tracht-digital.de` cookies so the
  same JWT works across `admin.` and `app.` subdomains.

## Don't

- Don't issue JWTs without recording the jti in `session`. Future
  revocation depends on it.
- Don't log the JWT_PRIVATE_KEY anywhere. error_log is fine for
  generic error messages but never include the key.
- Don't increase JWT_TTL_SECONDS beyond ~3600 without thinking about
  blast-radius of a leaked token.
