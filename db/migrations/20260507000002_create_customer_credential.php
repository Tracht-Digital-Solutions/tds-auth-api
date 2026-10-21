<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * The customer_credential table is created here (auth domain) but
 * populated and authenticated against in Phase 8 (tds-customer-api +
 * the customer-login action). Empty until then.
 */
final class CreateCustomerCredential extends AbstractMigration
{
    public function change(): void
    {
        $this->table('customer_credential', [
            'id' => true,
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
        ])
            ->addColumn('customer_id', 'integer')
            ->addColumn('email', 'string', ['limit' => 254])
            ->addColumn('password_hash', 'string', ['limit' => 255])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('updated_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP', 'update' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['email'], ['unique' => true, 'name' => 'uniq_email'])
            ->addIndex(['customer_id'], ['name' => 'idx_customer_id'])
            ->create();
    }
}
