<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * "Angemeldet bleiben" — long-lived remember-me tokens.
 *
 * The session JWT deliberately stays short-lived (an hour): downstream services
 * verify it against the JWKS and never consult this database, so a long JWT
 * would be a long NON-REVOCABLE credential. Staying signed in for 30 days is
 * therefore a *refresh* mechanism, not a longer token — a separate opaque
 * cookie backed by this table, exchanged at `POST /refresh` for a fresh JWT.
 *
 * Split selector/validator, the standard shape:
 *  - `selector` is looked up (indexed, unique) so the query never depends on a
 *    secret and cannot leak one through timing,
 *  - only a HASH of the validator is stored, so a stolen database dump does not
 *    yield usable cookies,
 *  - and the pair rotates on every use, which turns theft of a single cookie
 *    into a detectable anomaly rather than 30 days of silent access.
 *
 * Class name prefixed `Auth*` and the file name mapped to it (Phinx derives the
 * expected class from the file name): the gateway loads every service's
 * migrations into ONE process with one shared phinxlog.
 */
final class AuthCreateRememberToken extends AbstractMigration
{
    public function change(): void
    {
        $table = $this->table('app_user_remember', ['signed' => false]);
        $table
            ->addColumn('user_id', 'integer', ['signed' => false])
            // Public half of the cookie. Unique so a lookup is a single indexed
            // row, and fixed-length hex.
            ->addColumn('selector', 'string', ['limit' => 32])
            // sha256 hex of the validator half — never the validator itself.
            ->addColumn('validator_hash', 'string', ['limit' => 64])
            ->addColumn('expires_at', 'datetime')
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('last_used_at', 'datetime', ['null' => true])
            // Coarse provenance for the "aktive Anmeldungen" view; never used
            // for authentication (a UA header is attacker-controlled).
            ->addColumn('user_agent', 'string', ['limit' => 200, 'null' => true])
            ->addIndex(['selector'], ['unique' => true])
            ->addIndex(['user_id'])
            ->addIndex(['expires_at'])
            ->create();
    }
}
