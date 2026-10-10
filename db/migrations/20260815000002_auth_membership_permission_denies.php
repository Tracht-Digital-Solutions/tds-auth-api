<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Rights taken away from ONE person, overriding what their groups grant.
 *
 * A group is a bundle meant to be shared; the moment one member of it must not
 * have one of its rights, the alternatives were to clone the group for that
 * person or to drop them out of it and hand-grant the rest — both of which turn
 * the group from a living source into a snapshot that stops tracking.
 *
 * ```
 * effective = (direct ∪ groups) \ denies ∩ ceiling
 * ```
 *
 * ### NULL and `[]` mean the same thing here — deliberately unlike the ceiling
 *
 * `permission_ceiling` distinguishes them (`NULL` = no cap, `[]` = may hold
 * nothing), because a cap of "nothing" is a statement someone wants to make. A
 * deny list of "nothing" is just an empty deny list; there is no third state to
 * express, so nothing is gained by making callers pick between two spellings of
 * it. Do not "harmonise" the two columns later — they are different shapes for
 * a reason.
 *
 * A deny needs no ceiling check on write: it can only ever reduce.
 */
final class AuthMembershipPermissionDenies extends AbstractMigration
{
    public function change(): void
    {
        $this->table('app_user_company')
            ->addColumn('permission_denies', 'text', [
                'null' => true,
                'after' => 'permission_ceiling',
                'comment' => 'JSON list of rights withheld from this person; NULL and [] are equivalent',
            ])
            ->update();
    }
}
