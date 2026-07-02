<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateSession extends AbstractMigration
{
    public function change(): void
    {
        $this->table('session', [
            'id' => false,
            'primary_key' => ['jti'],
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
        ])
            // Explicit NOT NULL: MySQL 8 rejects a nullable PRIMARY KEY column
            // (error 1171), whereas MariaDB silently coerces it. Phinx's `uuid`
            // type doesn't emit NOT NULL on its own, so a fresh install on
            // MySQL 8 failed at CreateSession without this.
            ->addColumn('jti', 'uuid', ['limit' => 36, 'null' => false])
            ->addColumn('customer_id', 'integer', ['null' => true])
            ->addColumn('admin', 'boolean', ['default' => false])
            ->addColumn('expires_at', 'datetime')
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('revoked_at', 'datetime', ['null' => true])
            ->addIndex(['customer_id'], ['name' => 'idx_customer_id'])
            ->addIndex(['expires_at'], ['name' => 'idx_expires_at'])
            ->create();
    }
}
