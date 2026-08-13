<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * `display_name` — what the panel calls a person, as opposed to who they are.
 *
 * `name` stays the full legal-ish name an admin enters when creating the
 * account and is what appears on invoices, the blog byline and in user
 * management. `display_name` is the short form the user picks for themselves
 * ("Julian" rather than "Julian Tracht"), shown in the shell's profile menu.
 * Nullable and it falls back to `name`, so nothing changes for an account
 * that never sets one.
 *
 * Kept separate rather than letting users edit `name` directly: a self-service
 * `PATCH /me` that rewrote `name` would let anyone change how they appear in
 * an admin's user list and on a public blog author page, which is a different
 * decision from choosing a nickname for your own header.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthAddAppUserDisplayName extends AbstractMigration
{
    public function change(): void
    {
        $this->table('app_user')
            ->addColumn('display_name', 'string', [
                'limit' => 100,
                'null' => true,
                'after' => 'name',
            ])
            ->update();
    }
}
