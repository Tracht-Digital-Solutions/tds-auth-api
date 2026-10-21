<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Permission groups — the thing `PORTAL_ROLE_PRESETS` only pretended to be.
 *
 * The presets were UI sugar: the admin editor expanded one into a flat array on
 * click and nothing recorded which preset had been used, so editing a "role"
 * later changed nothing for anyone already carrying it. A group is a real row,
 * assignment is a real reference, and changing the group changes what its
 * members can do.
 *
 * ### `company_id = 0` means "platform group"
 *
 * NOT nullable, on purpose: MySQL treats NULLs as distinct in a UNIQUE index,
 * so `UNIQUE(company_id, slug)` with a nullable column would happily accept two
 * platform groups called `accounting`. `0` is a real value and collides
 * properly. It also makes "the groups visible to company 7" a single
 * `company_id IN (0, 7)`.
 *
 * ### Company-owned groups
 *
 * A company admin may create groups scoped to their own company (gated by
 * `auth_company_policy.allow_custom_groups`), and their permission set is
 * capped by the company's ceiling — enforced on write AND intersected again at
 * token-issue time, so lowering a ceiling takes effect immediately instead of
 * leaving a group that out-grants it.
 *
 * `is_system` marks the four seeded groups: their permissions stay editable
 * (that is the point of having them), but the slug and the row itself are
 * locked, because other things reference them by slug.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCreateGroup extends AbstractMigration
{
    public function change(): void
    {
        $this->table('auth_group', ['signed' => false])
            ->addColumn('company_id', 'integer', [
                'signed' => false,
                'default' => 0,
                'comment' => '0 = platform-wide group; otherwise the owning company',
            ])
            ->addColumn('slug', 'string', ['limit' => 64])
            ->addColumn('name', 'string', ['limit' => 120])
            ->addColumn('description', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('permissions', 'text', ['comment' => 'JSON list of permission keys'])
            ->addColumn('is_system', 'boolean', ['default' => false])
            ->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('updated_at', 'datetime', [
                'default' => 'CURRENT_TIMESTAMP',
                'update' => 'CURRENT_TIMESTAMP',
            ])
            ->addIndex(['company_id', 'slug'], ['unique' => true, 'name' => 'uq_group_slug'])
            ->addIndex(['company_id'], ['name' => 'idx_group_company'])
            ->create();
    }
}
