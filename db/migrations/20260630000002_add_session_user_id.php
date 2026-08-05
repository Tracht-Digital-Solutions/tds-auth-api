<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Adds a nullable `user_id` to the session table so a session can be tied to
 * the app_user that owns it. This lets the admin user-management revoke *all*
 * of a user's sessions at once (on disable / delete / password reset /
 * permission change) — which the previous customer_id/admin columns couldn't
 * target for admin principals.
 */
final class AddSessionUserId extends AbstractMigration
{
    public function change(): void
    {
        $this->table('session')
            ->addColumn('user_id', 'integer', ['null' => true, 'default' => null, 'after' => 'customer_id'])
            ->addIndex(['user_id'], ['name' => 'idx_session_user_id'])
            ->update();
    }
}
