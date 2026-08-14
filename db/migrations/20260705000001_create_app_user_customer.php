<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Company memberships for a login. Replaces the single `app_user.customer_id`
 * (+ `permissions`) tenancy with a many-to-many: one login can belong to several
 * companies, each with its own permission set.
 *
 * `customer_id` references the `customer` (company) table which lives in
 * tds-customer-api's DB, so — like `app_user.customer_id` — it carries NO foreign
 * key here. `permissions` is a JSON array (same catalog as PORTAL_PERMISSIONS).
 *
 * The legacy `app_user.customer_id` / `permissions` columns are kept as the
 * denormalised **primary** membership (the default active company + its
 * permissions) for backward compatibility; the repository keeps them in sync
 * with the first membership row.
 *
 * Backfill: every existing account with a customer_id becomes one membership.
 * Uses up()/down() because of the backfill.
 */
final class CreateAppUserCustomer extends AbstractMigration
{
    public function up(): void
    {
        $this->table('app_user_customer', [
            'id' => true,
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
        ])
            ->addColumn('user_id', 'integer', ['signed' => false])
            ->addColumn('customer_id', 'integer', ['signed' => false])
            ->addColumn('permissions', 'text')
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['user_id', 'customer_id'], ['unique' => true, 'name' => 'uniq_user_customer'])
            ->addIndex(['user_id'], ['name' => 'idx_user'])
            ->addForeignKey('user_id', 'app_user', 'id', ['delete' => 'CASCADE'])
            ->create();

        // Backfill one membership per account that currently has a company.
        $this->execute(
            'INSERT INTO app_user_customer (user_id, customer_id, permissions, created_at) '
            . 'SELECT id, customer_id, permissions, NOW() FROM app_user WHERE customer_id IS NOT NULL'
        );
    }

    public function down(): void
    {
        $this->table('app_user_customer')->drop()->save();
    }
}
