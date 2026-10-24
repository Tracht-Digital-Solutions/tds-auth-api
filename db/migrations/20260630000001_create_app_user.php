<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Unified login identity. Replaces customer_credential as the credential
 * store and adds admin identity + per-account portal permissions.
 *
 * One row = one login that spans both panels: `is_admin` grants admin-panel
 * access; a non-null `customer_id` ties the account to a company (tenant) in
 * the customer portal, scoped by `permissions` (JSON array of permission
 * keys — mirrors PORTAL_PERMISSIONS in tds-shared). Multiple rows may share
 * the same `customer_id` (several accounts per company).
 *
 * Existing customer_credential rows are backfilled here with full portal
 * access. The customer_credential table is intentionally left in place for a
 * safe rollback window — code no longer reads it.
 */
final class CreateAppUser extends AbstractMigration
{
    public function up(): void
    {
        $this->table('app_user', [
            'id' => true,
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
        ])
            ->addColumn('email', 'string', ['limit' => 254])
            ->addColumn('password_hash', 'string', ['limit' => 255])
            ->addColumn('name', 'string', ['limit' => 200, 'null' => true, 'default' => null])
            ->addColumn('is_admin', 'boolean', ['default' => false])
            ->addColumn('customer_id', 'integer', ['null' => true, 'default' => null])
            ->addColumn('permissions', 'text')
            ->addColumn('status', 'string', ['limit' => 20, 'default' => 'active'])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('updated_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP', 'update' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['email'], ['unique' => true, 'name' => 'uniq_app_user_email'])
            ->addIndex(['customer_id'], ['name' => 'idx_app_user_customer_id'])
            ->create();

        // Backfill existing customer logins with full portal access.
        if ($this->hasTable('customer_credential')) {
            $fullPermissions = json_encode([
                'projects:read',
                'invoices:read',
                'invoices:pay',
                'documents:read',
                'documents:write',
                'messages:read',
                'messages:write',
            ], JSON_THROW_ON_ERROR);

            $this->execute(
                'INSERT INTO app_user '
                . '(email, password_hash, name, is_admin, customer_id, permissions, status, created_at, updated_at) '
                . 'SELECT email, password_hash, NULL, 0, customer_id, '
                . $this->getAdapter()->getConnection()->quote($fullPermissions)
                . ", 'active', created_at, updated_at FROM customer_credential"
            );
        }
    }

    public function down(): void
    {
        $this->table('app_user')->drop()->save();
    }
}
