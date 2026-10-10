<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * `session.created_at` to microsecond resolution, so `listActive()` can keep the
 * "newest first" promise it makes.
 *
 * The column was plain `DATETIME` (1-second resolution) and `record()` wrote it
 * with `NOW()`. Any two sessions issued in the same second therefore tied, and
 * the sort fell through to the `jti` tiebreaker — which is a **random UUIDv4**.
 * That made the order deterministic (the original bug) but still not
 * chronological: the admin session list could show a fresh login below one from
 * earlier in the same second. Same-second logins are not exotic here; a refresh
 * plus a passkey sign-in land together routinely.
 *
 * `DATETIME(6)` is the smallest change that makes the documented behaviour true.
 * The `jti` tiebreaker stays as the last resort for the (now vanishingly rare)
 * exact tie, so ordering remains total.
 *
 * MySQL-8-safe: `MODIFY` keeps the column NOT NULL and re-states the default at
 * the same precision — MySQL rejects a `CURRENT_TIMESTAMP` default whose
 * precision differs from the column's. Existing rows keep their value and simply
 * gain `.000000`.
 */
final class AuthSessionCreatedAtMicroseconds extends AbstractMigration
{
    public function up(): void
    {
        $this->execute(
            'ALTER TABLE session '
            . 'MODIFY created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)'
        );
    }

    public function down(): void
    {
        $this->execute(
            'ALTER TABLE session '
            . 'MODIFY created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP'
        );
    }
}
