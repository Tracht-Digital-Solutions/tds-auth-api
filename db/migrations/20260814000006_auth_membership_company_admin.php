<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * The company admin flag, and the per-user ceiling.
 *
 * ### Both sit on the MEMBERSHIP, not on the user
 *
 * Administering a company is a property of belonging to it: the same login can
 * run company A and be an ordinary user at company B. A boolean on `app_user`
 * could not express that, and would quietly promote someone in every company
 * they join.
 *
 * `permission_ceiling` is the per-user cap the brief asked for — "das kann auch
 * für einzelne Benutzer getan werden". NULL inherits the company's
 * `allowed_permissions`; a JSON array narrows it further for this one person.
 * It is writable only by a PLATFORM admin: it is absent from the field
 * whitelist of every `/company/*` route, which is what stops a company admin
 * from raising their own ceiling.
 *
 * Everything defaults to "as before": no company admins exist until someone is
 * promoted, and no ceilings exist until one is set.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthMembershipCompanyAdmin extends AbstractMigration
{
    public function change(): void
    {
        $this->table('app_user_company')
            ->addColumn('is_company_admin', 'boolean', [
                'default' => false,
                'after' => 'company_id',
            ])
            ->addColumn('permission_ceiling', 'text', [
                'null' => true,
                'comment' => 'JSON list; NULL = inherit the company policy',
            ])
            ->update();
    }
}
