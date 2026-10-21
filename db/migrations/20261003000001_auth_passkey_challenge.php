<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Answered WebAuthn challenges, so a captured challenge cookie and assertion
 * cannot be replayed within the cookie's five minutes (see UsedChallenges).
 *
 * NOT NULL primary key (MySQL 8 rejects a nullable one). Class prefixed
 * `Auth*`: the gateway loads every service's migrations into one phinxlog.
 */
final class AuthPasskeyChallenge extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_passkey_challenge', ['id' => false, 'primary_key' => ['challenge_hash']])
            ->addColumn('challenge_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('expires_at', 'datetime', ['null' => false])
            ->addIndex(['expires_at'], ['name' => 'idx_passkey_challenge_expiry'])
            ->create();
    }
}
