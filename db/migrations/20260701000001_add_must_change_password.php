<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Adds `must_change_password` to app_user. When set, the login response and
 * /me carry the flag and both panels bounce the user to a forced
 * change-password screen before they can use the app. Cleared the moment the
 * user sets their own password (ChangePasswordAction).
 *
 * Set for: the seeded bootstrap admin, any admin-reset temp password, and
 * generated temp passwords on user creation.
 */
final class AddMustChangePassword extends AbstractMigration
{
    public function up(): void
    {
        $this->table('app_user')
            ->addColumn('must_change_password', 'boolean', [
                'default' => false,
                'after' => 'status',
            ])
            ->update();
    }

    public function down(): void
    {
        $this->table('app_user')->removeColumn('must_change_password')->update();
    }
}
