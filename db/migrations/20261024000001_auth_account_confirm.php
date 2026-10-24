<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * One-time confirmation tokens of self-registered accounts (POST /register).
 *
 * The row carries the password hash and the name of THAT registration, not
 * the account: whoever registers an address first must not be able to plant a
 * password the real owner later activates. Only the clicked link's own hash
 * is applied, and only the mailbox owner can click it.
 *
 * Only the SHA-256 of the token is stored. Expiry is written and compared with
 * NOW() alone. NOT NULL primary key (MySQL 8); class prefixed `Auth*` because
 * the gateway loads every service's migrations into one phinxlog.
 */
final class AuthAccountConfirm extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_account_confirm', ['id' => false, 'primary_key' => ['token_hash']])
            ->addColumn('token_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('password_hash', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('name', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('expires_at', 'datetime', ['null' => false])
            ->addColumn('used_at', 'datetime', ['null' => true])
            ->addColumn('created_at', 'datetime', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['user_id'], ['name' => 'idx_account_confirm_user'])
            ->addIndex(['expires_at'], ['name' => 'idx_account_confirm_expiry'])
            ->create();
    }
}
