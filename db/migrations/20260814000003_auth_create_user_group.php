<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Group assignments — who is in which group, **and in which company**.
 *
 * ### Why the assignment carries `company_id`
 *
 * A login can belong to several companies, and routinely needs a different
 * role in each: "Buchhaltung" at A, "Nur Lesen" at B. Storing group ids on the
 * membership row (`app_user_company.group_ids` as JSON) would express that too,
 * but loses referential integrity and cannot answer "who is in this group",
 * which the admin UI needs in order to warn before an edit.
 *
 * `company_id = 0` is a GLOBAL assignment: the group applies in every scope.
 * That is what makes a platform-wide role possible without inserting one row
 * per company.
 *
 * Unlike `company_id` on `app_user_company` — an unenforced pointer into
 * another database — both foreign keys here are real: `app_user` and
 * `auth_group` live in this schema, so deleting a user or a group takes its
 * assignments with it instead of leaving rows that grant nothing to nobody.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCreateUserGroup extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_user_group', ['signed' => false])
            ->addColumn('user_id', 'integer', ['signed' => false])
            ->addColumn('group_id', 'integer', ['signed' => false])
            ->addColumn('company_id', 'integer', [
                'signed' => false,
                'default' => 0,
                'comment' => 'scope the group applies in; 0 = every scope',
            ])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['user_id', 'group_id', 'company_id'], [
                'unique' => true,
                'name' => 'uq_user_group',
            ])
            ->addIndex(['user_id'], ['name' => 'idx_user_group_user'])
            ->addIndex(['group_id'], ['name' => 'idx_user_group_group'])
            ->addForeignKey('user_id', 'app_user', 'id', ['delete' => 'CASCADE'])
            ->addForeignKey('group_id', 'auth_group', 'id', ['delete' => 'CASCADE'])
            ->create();
    }
}
