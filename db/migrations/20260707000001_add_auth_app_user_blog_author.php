<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Adds blog-authorship + profile fields to app_user:
 *  - `is_blog_author`: grants blog-authoring access in tds-admin (parallel to
 *    is_admin / is_support_agent), carried in the JWT as the `blog_author`
 *    claim so tds-content-api can gate blog writes without a lookup.
 *  - `avatar_url`: public profile-picture URL. The file itself is stored via
 *    tds-content-api's existing upload infra (served from /uploads); auth-api
 *    only keeps the resulting URL string.
 *  - `bio`: short author bio shown on the public blog author page.
 *
 * Class name is prefixed `Auth…` to stay unique across the four API services —
 * the gateway loads every service's migrations into one PHP process, and a
 * reused class name fatals on redeclaration.
 */
final class AddAuthAppUserBlogAuthor extends AbstractMigration
{
    public function up(): void
    {
        $this->table('app_user')
            ->addColumn('avatar_url', 'string', ['limit' => 500, 'null' => true, 'default' => null, 'after' => 'name'])
            ->addColumn('bio', 'text', ['null' => true, 'default' => null, 'after' => 'avatar_url'])
            ->addColumn('is_blog_author', 'boolean', ['default' => false, 'after' => 'is_support_agent'])
            ->update();
    }

    public function down(): void
    {
        $this->table('app_user')
            ->removeColumn('avatar_url')
            ->removeColumn('bio')
            ->removeColumn('is_blog_author')
            ->update();
    }
}
