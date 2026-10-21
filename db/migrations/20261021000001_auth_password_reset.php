<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * One-time password-reset tokens (POST /password-reset). Only the SHA-256 of
 * the token is stored: a leaked row cannot be turned back into a working link.
 * `expires_at` and `used_at` are written and compared with NOW() alone, so the
 * Berlin-pinned session clock is the only convention involved.
 *
 * NOT NULL primary key (MySQL 8 rejects a nullable one). Class prefixed
 * `Auth*`: the gateway loads every service's migrations into one phinxlog.
 */
final class AuthPasswordReset extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_password_reset', ['id' => false, 'primary_key' => ['token_hash']])
            ->addColumn('token_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('expires_at', 'datetime', ['null' => false])
            ->addColumn('used_at', 'datetime', ['null' => true])
            ->addColumn('created_at', 'datetime', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['user_id'], ['name' => 'idx_password_reset_user'])
            ->addIndex(['expires_at'], ['name' => 'idx_password_reset_expiry'])
            ->create();
    }
}
