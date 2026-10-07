# Pitfalls

- **Don't issue JWTs without recording the `jti` in `session`.** Revocation depends on it.
- **Don't log `JWT_PRIVATE_KEY`** anywhere; generic `error_log` messages only.
- **Don't raise `JWT_TTL_SECONDS` beyond ~3600** without weighing the blast radius of a leaked,
  non-revocable token.
- **Env precedence trap.** `$_ENV[$key] ?? getenv($key) ?: $default` parses as
  `($_ENV[$key] ?? getenv($key)) ?: $default` and clobbers legitimately falsy values. Use explicit
  `?? false`. This hit all four APIs via copy-paste.
- **Add `CorsMiddleware` after `addRoutingMiddleware()`.** Slim is LIFO; added earlier, routing 405s every
  OPTIONS preflight and browsers block all cross-origin requests, including logins. `tests/PreflightTest.php`
  sends OPTIONS through the real `Bootstrap::createApp()`; unit-testing the middleware alone can't catch the
  ordering.
- **Run `php -S` with `public/router.php`** (`composer start` does). Otherwise `/.well-known/jwks.json` never
  reaches Slim and every consumer's JWT verification breaks.
- **Don't filter permissions on read** (see [user-model.md](user-model.md)).
- **Don't answer 403 where 404 hides existence** (foreign sessions, non-member users).
- **Don't rename a column without grepping SQL literals** (see [database.md](database.md)).
- **Audit permission rows before deploying a change to permission handling**; data that was silently dropped
  on read becomes effective once read filtering is gone.
