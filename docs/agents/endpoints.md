# Endpoints

`tds-gateway-api` strips the `/auth` prefix (`…/auth/admin/login` → `/admin/login`); routes mount at root.

## Login and session

| Route | Notes |
|---|---|
| `POST /login` (alias `POST /customer/login`) | Email + password → JWT. `password_verify` with a dummy verify on miss (constant time). Disabled accounts → 403. Returns `isAdmin`, `customerId`, `permissions`, flags |
| `DELETE /logout` (alias `DELETE /admin/login`) | Revoke the session and clear cookies |
| `GET /me` | Current principal, incl. `expiresAt` (Unix seconds from `exp`, or `null`) so frontends can bounce an expired session before paint |
| `PUT /password` (alias `PUT /customer/password`) | Change own password. Revokes **all** the user's sessions and remember tokens, then issues a fresh session for this device |
| `POST /refresh` | Rotate the access token; see [sessions-and-keys.md](sessions-and-keys.md) |
| `GET /.well-known/jwks.json` | Public key as JWKS |
| Passkeys | See [sessions-and-keys.md](sessions-and-keys.md#passkeys-webauthn) |

`mustChangePassword` is surfaced by `/login` and `/me` and cleared by `PUT /password`. Admin-issued
temporary passwords (user create, `POST /admin/users/{id}/reset-password`) set it too.

## Self-service profile (any session, always the user in the token)

- **`PATCH /me` accepts exactly one field, `displayName`.** Not `name` (admin-maintained, drives the blog
  byline), not `email` (login identity, needs a confirmation flow), no flags. Unknown keys are ignored
  (clients often send back a whole `/me` object). Nothing authorisation-relevant changes, so **no sessions
  are revoked**; a test pins the action's constructor arity so a `SessionRepository` can't sneak in.
- **`POST` / `DELETE /me/avatar`** — see below.
- **`GET /me/sessions`** scopes in SQL (`listActiveForUser`), never by filtering `listActive()` in PHP.
  `current: true` marks the requesting session.
- **`DELETE /me/sessions/{jti}`** proves ownership via `ownerOf()` and answers **404** for unknown,
  foreign, revoked and expired alike (403 would be an existence oracle). Revoking your own current
  session is allowed.

## Avatar

**`GET /users/{id}/avatar` is unauthenticated, by necessity:** a cross-origin `<img src>` sends no
credentials, and inlining avatars would bloat `/me` and defeat caching. It exposes a picture the person
chose as their public representation; no avatar and no user both answer 404.

- Bytes live in **`app_user_avatar` (MEDIUMBLOB)**, not on disk: no writable directory is needed on the
  Plesk host.
- Uploads are sniffed with `getimagesizefromstring`, never trusted from `Content-Type`. **SVG is rejected**
  (it can carry `<script>`, served from the cookie's origin).
- No server-side resizing (no guaranteed `ext-gd`); the panel downscales in a `<canvas>`, and 2 MiB is the
  ceiling.
- The public URL is built from **`JWT_ISSUER`**, not a new env var.

## Admin (per-admin JWT: `JwtAuthMiddleware(requireAdmin: true)`)

- `GET` / `POST /admin/users`, `PATCH` / `DELETE /admin/users/{id}`,
  `POST /admin/users/{id}/reset-password`. Authorisation-relevant changes (`is_admin`,
  `is_support_agent`, permissions, status, memberships) revoke the user's sessions.
- Membership payloads are parsed by `MembershipPayload`: drops non-positive company ids, non-object
  entries, unknown keys and permissions without a company. `present()` distinguishes "said nothing about
  memberships" (leave them) from `memberships: []` (revoke all).
- `GET /admin/sessions`, `DELETE /admin/sessions/{jti}`. `session.created_at` is **`DATETIME(6)`** and
  `record()` writes `NOW(6)`: at second resolution, sessions created in the same second sort by a random
  UUID tiebreaker and "newest first" is false.
- Company-scoped administration lives under `/company/{companyId}/*`; see
  [user-model.md](user-model.md#company-admins-companycompanyid).

## Server to server

`POST /admin/customer-credentials`, gated by the **service token** (`SERVICE_TOKEN`, falling back to
`ADMIN_TOKEN`). `tds-customer-api` calls it after inserting a company; it creates the matching `app_user`
with full portal access.

## Bootstrapping the first admin

Both paths set `must_change_password`:

- **Seed migration** `20260701000002_seed_bootstrap_admin`: on the first migrate, if no admin exists,
  seeds one from `ADMIN_BOOTSTRAP_EMAIL` / `ADMIN_BOOTSTRAP_PASSWORD` (defaults `admin@tracht-digital.de`
  / `tds-setup-admin`). Idempotent.
- **Script:** `composer create-admin -- you@example.com [password]`.

The gateway installer creates the first admin directly instead, because the in-process migrator doesn't
populate the process env the seed reads.
