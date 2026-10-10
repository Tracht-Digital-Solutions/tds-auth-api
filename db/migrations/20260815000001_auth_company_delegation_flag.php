<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * May this company have company admins at all?
 *
 * Delegation is now an explicit per-company grant: without it nobody inside the
 * company can create or manage users, and no groups can be assigned from there.
 *
 * ### This one field breaks "no row = unlimited" on purpose
 *
 * Every other column here is permissive when absent, which is what makes the
 * policy table opt-in. `allow_company_admins` defaults to **0** instead, for the
 * same reason `allow_custom_groups` does: it does not LIMIT a capability, it
 * hands one out. A company that nobody has configured must not silently be able
 * to administer itself.
 *
 * Consequence worth knowing before promoting anyone: setting
 * `app_user_company.is_company_admin = 1` on a company without this flag does
 * nothing visible. The flag comes first — see RUNBOOK.md.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCompanyDelegationFlag extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_company_policy')
            ->addColumn('allow_company_admins', 'boolean', [
                'default' => false,
                'after' => 'allow_custom_groups',
                'comment' => 'May this company have company admins? Absent policy row = false.',
            ])
            ->update();
    }
}
