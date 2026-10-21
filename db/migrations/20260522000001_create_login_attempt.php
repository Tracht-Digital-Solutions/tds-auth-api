<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateLoginAttempt extends AbstractMigration
{
    public function change(): void
    {
        $this->table('login_attempt', [
            'id' => true,
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
        ])
            ->addColumn('bucket', 'string', ['limit' => 100, 'comment' => 'admin:{ip} | customer:{ip}'])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['bucket', 'created_at'], ['name' => 'idx_bucket_created'])
            ->addIndex(['created_at'], ['name' => 'idx_created'])
            ->create();
    }
}
