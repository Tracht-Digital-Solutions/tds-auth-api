<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * What the platform admin allows a company to do on its own.
 *
 * ### Why this lives in auth-api and not in the Firmen extension
 *
 * The extension owns the company DIRECTORY (name, email, phone, note). A seat
 * cap and a permission ceiling are not directory data — they are authorization
 * constraints on a write that **only auth-api performs**. Putting them in the
 * extension would make every company-scoped user write depend on a synchronous
 * call into the composed API, so user management would fail whenever that
 * service is down. auth-api is the core dependency of both architectures and
 * has to keep working on its own. (The admin UI still lives wherever it reads
 * best — data location and UI location are separate decisions.)
 *
 * ### Empty means unlimited, and that is why the feature is opt-in
 *
 * A company with no row here has no seat cap and no ceiling, i.e. exactly
 * today's behaviour. Nothing changes for anyone until an admin sets a policy.
 *
 * - `max_users` NULL → unlimited.
 * - `allowed_permissions` NULL → no ceiling. An empty JSON array `[]` is
 *   different and means "may grant nothing" — the distinction is real, so the
 *   column is nullable rather than defaulting to `[]`.
 * - `allow_custom_groups` → may the company admin create groups of their own?
 *
 * `company_id` is a pointer into another database (the composed `company`
 * table), so it carries no foreign key — the same documented convention as
 * `app_user_company.company_id`.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCreateCompanyPolicy extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_company_policy', [
            'id' => false,
            'primary_key' => ['company_id'],
            'signed' => false,
        ])
            // Explicit NOT NULL: MySQL 8 rejects a nullable PRIMARY KEY column
            // (error 1171), whereas MariaDB silently coerces it. Phinx defaults
            // every addColumn() to nullable. Guarded by MigrationDialectTest.
            ->addColumn('company_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('max_users', 'integer', [
                'signed' => false,
                'null' => true,
                'comment' => 'NULL = unlimited',
            ])
            ->addColumn('allowed_permissions', 'text', [
                'null' => true,
                'comment' => 'JSON list; NULL = no ceiling, [] = may grant nothing',
            ])
            ->addColumn('allow_custom_groups', 'boolean', ['default' => false])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('updated_at', 'datetime', [
                'default' => 'CURRENT_TIMESTAMP',
                'update' => 'CURRENT_TIMESTAMP',
            ])
            ->create();
    }
}
