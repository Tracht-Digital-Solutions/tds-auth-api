# tds-auth-api runbook

Operational procedures for `tds-auth-api`. Keep this updated as the
service changes — the goal is "future me doesn't have to re-derive
this at 2am".

---

## Key rotation (planned)

Use this when:
- A new keypair is needed on a regular schedule (we don't currently
  have one — see _Open questions_).
- The current `keys/private.pem` is suspected compromised.
- Algorithm or key-size policy changes.

### Plan ahead

- Pick the rotation moment for a quiet window. Tokens in flight at
  rotation time stay valid until they expire (default `JWT_TTL_SECONDS`
  = 1 h, refresh = 30 days). Sessions actively refreshing keep working
  through the overlap because both keys serve from JWKS.
- Notify consumers (`tds-content-api`, `tds-customer-api`, both
  frontend repos) that the JWKS will change so they can clear their
  in-memory JWKS cache on next request — usually not strictly needed
  since `JWKS_CACHE_TTL` defaults to 600 s.

### Procedure

1. **Generate the new keypair locally**, on a trusted machine that
   already has the repo checked out:

   ```bash
   composer install
   composer keygen   # writes keys/private.pem + keys/public.pem
   mv keys/private.pem keys/private-NEW.pem
   mv keys/public.pem  keys/public-NEW.pem
   ```

2. **Pick a new `kid`.** Convention: `tds-auth-<year>-<n>`, e.g.
   `tds-auth-2026-2`. Save it.

3. **Add the NEW public key alongside the OLD one in JWKS.** Open a
   PR that updates `JwksAction` to return BOTH keys (each with its
   own `kid`):
   - Stash the new public key under `keys/public-NEW.pem`.
   - Extend `JwksAction` to read both files and emit a two-element
     `keys` array. `kid` distinguishes them; verifiers pick the right
     one off the token header.
   - Merge + deploy. JWKS now serves the old key (signing) plus the
     new key (waiting).

4. **Wait one JWKS_CACHE_TTL window** (default 10 min) so consumers
   refresh their cached JWKS and start accepting the new `kid`.

5. **Switch the signing key.** On the production host:
   - Paste the contents of `keys/private-NEW.pem` into the shared
     `.env` as `JWT_PRIVATE_KEY` (newlines escaped to `\n` if the
     `.env` parser can't do multiline).
   - Set `JWT_KEY_ID` to the new `kid`.
   - Restart / cycle the PHP-FPM pool if applicable (re-triggering the
     deploy hook — e.g. an empty commit to `main` — is the cleanest way
     to bounce processes).
   - From now on, newly-issued tokens carry the new `kid`.

6. **Wait `JWT_TTL_SECONDS + JWT_REFRESH_TTL_SECONDS`** (default
   31 days). After that, no token signed by the old key can still
   be in circulation.

7. **Drop the old key from JWKS.** Second PR: revert `JwksAction`
   to single-key, remove `keys/public-OLD.pem` from disk + repo,
   merge + deploy.

8. **Save the new keypair to password manager** for disaster
   recovery, then delete the local `keys/private-NEW.pem`.

### Compressed timeline

| Window | What runs in production |
|---|---|
| t=0 | OLD signs, JWKS serves OLD only |
| t=0 → t=10 min | OLD signs, JWKS serves OLD + NEW (overlap PR landed) |
| t=10 min | Switch: NEW signs, JWKS serves OLD + NEW |
| t=10 min → t≈31 days | NEW signs, OLD still valid until its tokens age out |
| t≈31 days | Final cleanup PR: NEW signs, JWKS serves NEW only |

### Why two PRs

The single-key emergency replacement (one PR that swaps the key
in place) is tempting but invalidates every refresh token in
circulation — every customer is logged out. The two-PR procedure
preserves session continuity.

### Emergency rotation (key compromise)

If the private key leaked, skip steps 3-4 and immediately rotate
in-place. Every active session is invalidated; customers must log
in again. Update `JWT_PRIVATE_KEY` + `JWT_KEY_ID` in shared `.env`,
deploy, then start the slow rollout for the next planned rotation.

---

## Backup + restore

- The only secret material here is `keys/private.pem` (or
  `JWT_PRIVATE_KEY` in the production host shared `.env`). It's not in version
  control — `keys/private.pem` is gitignored.
- **Backup**: save the private key to your password manager.
  Re-creating one means every active session is invalidated.
- **Restore**: paste back into the shared `.env`, set the matching
  `JWT_KEY_ID`, deploy. Done.

---

## Open questions

- Do we want a scheduled rotation? If yes, six months feels
  reasonable. There's no monitoring / cron that nags about it
  today — manually note the date.
- `keys/public.pem` is committed (only the private key is
  gitignored) so a fresh clone serves JWKS without re-running
  `composer keygen`. Documented in `AGENTS.md`.
