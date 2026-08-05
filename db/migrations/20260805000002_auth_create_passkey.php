<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Passkeys (WebAuthn credentials).
 *
 * One row per registered authenticator. `credential_id` is the base64url form
 * of the raw credential id — indexed unique because sign-in looks the user up
 * BY it: a passkey login carries no email, the authenticator names the account.
 *
 * `sign_count` is the authenticator's monotonic counter. It is stored so a
 * *decreasing* counter can be spotted, which is the one signal WebAuthn gives
 * that a credential may have been cloned. Many modern authenticators (Apple,
 * Windows Hello, most security keys in resident mode) always report 0, so a
 * zero counter is normal and must not be treated as an attack.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCreatePasskey extends AbstractMigration
{
    public function change(): void
    {
        $table = $this->table('app_user_passkey', ['signed' => false]);
        $table
            ->addColumn('user_id', 'integer', ['signed' => false])
            // base64url of the raw credential id. 255 covers the 1023-byte
            // maximum for every authenticator in practice (ids are ≤ 64 bytes
            // outside of the largest attestation formats).
            ->addColumn('credential_id', 'string', ['limit' => 255])
            // PEM public key as the verifier consumes it.
            ->addColumn('public_key', 'text')
            ->addColumn('sign_count', 'integer', ['signed' => false, 'default' => 0])
            // User-chosen label ("MacBook", "iPhone") so a list of passkeys is
            // actionable — without one, revoking the right one is guesswork.
            ->addColumn('name', 'string', ['limit' => 100, 'null' => true])
            ->addColumn('transports', 'string', ['limit' => 100, 'null' => true])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('last_used_at', 'datetime', ['null' => true])
            ->addIndex(['credential_id'], ['unique' => true])
            ->addIndex(['user_id'])
            ->create();
    }
}
