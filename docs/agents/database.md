# Database, migrations and time

## Migrations must survive MySQL 8

Production is MySQL 8; dev, CI and every DB test run MariaDB 11, which is more permissive. Phinx defaults
every `addColumn()` to nullable, so a table with `'primary_key' => ['user_id']` whose column doesn't say
`'null' => false` is coerced by MariaDB and rejected by MySQL 8:

```
SQLSTATE[42000] 1171 All parts of a PRIMARY KEY must be NOT NULL
```

`app_user_avatar` and `auth_company_policy` shipped that way; the only symptom was the gateway's
`/install.php` dying mid-run on a fresh host. Two guards:

| Guard | Where | Catches |
|---|---|---|
| `tests/Support/MigrationDialectTest` | this suite, no DB | nullable primary-key columns, instantly |
| *Migrate against MySQL 8* step | `_pipeline.yml`, every run | everything else; applies the whole set to an empty `mysql:8` (host port 3307) |

- `phinx.php` falls back to `getenv()`, because PHP's `variables_order` (`GPCS`) leaves `$_ENV` empty from
  the real environment. A real `.env` still wins.
- The gateway repeats the rehearsal across all services during its assemble.
- Editing an already-applied migration is acceptable only when the result is schema-identical (as with
  that MariaDB coercion). **Never change a released migration's version.**

## A DB test that writes its own DDL only tests itself

A migration renamed `session.customer_id` to `company_id`, but `PdoSessionRepository` kept the old name.
**Every successful login returned 500** (the jti is recorded right after the password check) while wrong
passwords still returned a clean 401. `PdoSessionRepositoryTest` built its own table with stale
hand-written DDL and passed.

| Guard | Where | Catches |
|---|---|---|
| `tests/Support/RenamedColumnSqlTest` | this suite, no DB | any **SQL string literal** naming a retired identifier |
| The `setUp()` comment in `PdoSessionRepositoryTest` | that suite | hand-written DDL drifting from migrations |

`RenamedColumnSqlTest` inspects only string literals containing SQL keywords, because `customer_id`
legitimately survives as the deprecated JWT claim, the `?customer_id=` alias and the
`customer_credential` table. **Add to its `RETIRED` map whenever a migration renames something, and grep
the repositories in the same change.**

## Time zones: Europe/Berlin, pinned

`Bootstrap::createApp()` pins PHP (`Infrastructure\TimeZone::pinPhp()`) and `Database::connect()` pins
every DB session (`pinSession()`) to Europe/Berlin, matching production. Every `NOW()` /
`CURRENT_TIMESTAMP` column holds Berlin wall-clock time; CLI PHP and CI containers default to UTC.

- It pins a default and converts nothing. A `gmdate()` / `UTC_TIMESTAMP()` value stays UTC and needs a
  reader that names the zone. This service writes none today.
- **Never compare the two conventions in one condition.**
- Official MySQL/MariaDB images ship empty time-zone tables; a session already at Berlin's offset is left
  alone, any other gets the current offset (`tests/Infrastructure/TimeZoneTest`).
- Moving to UTC is a separate cross-service decision, not a refactor.

## Session timestamps

`session.created_at` is `DATETIME(6)` and written with `NOW(6)`; keep the test DDL at `(6)` too (see
[endpoints.md](endpoints.md#admin-per-admin-jwt-jwtauthmiddlewarerequireadmin-true)).
