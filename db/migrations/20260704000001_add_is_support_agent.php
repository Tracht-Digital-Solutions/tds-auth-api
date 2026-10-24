<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Adds `is_support_agent` to app_user. Marks the subset of admin accounts that
 * support tickets can be assigned to (the "Bearbeiter"). Independent of
 * `is_admin` and only meaningful for admins — a non-admin can never be an agent.
 *
 * Surfaced on /me and in the login response, and carried in the JWT as the
 * `support_agent` claim so downstream services can read it without a lookup.
 * Toggling it revokes the user's sessions (UpdateUserAction) so the claim
 * refreshes on the next login.
 */
final class AddIsSupportAgent extends AbstractMigration
{
    public function up(): void
    {
        $this->table('app_user')
            ->addColumn('is_support_agent', 'boolean', [
                'default' => false,
                'after' => 'is_admin',
            ])
            ->update();
    }

    public function down(): void
    {
        $this->table('app_user')->removeColumn('is_support_agent')->update();
    }
}
