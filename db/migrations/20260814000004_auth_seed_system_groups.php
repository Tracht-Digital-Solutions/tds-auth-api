<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Seeds the four platform groups from what used to be `PORTAL_ROLE_PRESETS`.
 *
 * ### The permission lists are hard-coded here, deliberately
 *
 * A migration must never import a moving constant. `PORTAL_ROLE_PRESETS` lives
 * in tds-shared and is `@deprecated` as of this change; if this file read it,
 * re-running the migration on a fresh database a year from now would seed
 * whatever that constant says *then*, and two environments would disagree about
 * what "Buchhaltung" means. These lists are a snapshot, and that is correct.
 *
 * ### No assignments are backfilled
 *
 * It is tempting to look at an existing user whose permission array happens to
 * equal the "Buchhaltung" set and assign them the group. That is a guess, and
 * it would silently change their access the first time someone edits the group.
 * Existing users keep their direct grants; groups are opt-in from here.
 *
 * Idempotent (`INSERT IGNORE` against the unique slug), so re-running against a
 * database that already has them is a no-op rather than a duplicate-key abort
 * that takes every other service's migration down with it.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthSeedSystemGroups extends AbstractMigration
{
    public function up(): void
    {
        // Snapshot of tds-shared's PORTAL_ROLE_PRESETS at the time of writing.
        $groups = [
            [
                'slug' => 'full',
                'name' => 'Vollzugriff',
                'description' => 'Alle Portal-Rechte.',
                'permissions' => [
                    'projects:read', 'invoices:read', 'invoices:pay',
                    'documents:read', 'documents:write',
                    'messages:read', 'messages:write',
                    'tickets:read', 'tickets:write',
                ],
            ],
            [
                'slug' => 'accounting',
                'name' => 'Buchhaltung',
                'description' => 'Rechnungen und Belege.',
                'permissions' => ['invoices:read', 'invoices:pay', 'documents:read'],
            ],
            [
                'slug' => 'project_team',
                'name' => 'Projektteam',
                'description' => 'Projekte, Dokumente, Nachrichten und Tickets.',
                'permissions' => [
                    'projects:read', 'documents:read', 'documents:write',
                    'messages:read', 'messages:write',
                    'tickets:read', 'tickets:write',
                ],
            ],
            [
                'slug' => 'read_only',
                'name' => 'Nur Lesen',
                'description' => 'Alles ansehen, nichts ändern.',
                'permissions' => [
                    'projects:read', 'invoices:read', 'documents:read',
                    'messages:read', 'tickets:read',
                ],
            ],
        ];

        // `getAdapter()->getConnection()->quote()` is how this repo's other
        // seed quotes (see 20260701000002); the adapter itself is wrapped in a
        // TimedOutputAdapter during a run and exposes no quoting helper.
        $conn = $this->getAdapter()->getConnection();

        foreach ($groups as $group) {
            $this->execute(sprintf(
                'INSERT IGNORE INTO auth_group (company_id, slug, name, description, permissions, is_system)
                 VALUES (0, %s, %s, %s, %s, 1)',
                $conn->quote($group['slug']),
                $conn->quote($group['name']),
                $conn->quote($group['description']),
                $conn->quote((string) json_encode($group['permissions'])),
            ));
        }
    }

    public function down(): void
    {
        $this->execute('DELETE FROM auth_group WHERE company_id = 0 AND is_system = 1');
    }
}
