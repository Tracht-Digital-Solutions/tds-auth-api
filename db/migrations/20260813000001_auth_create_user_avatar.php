<?php
declare(strict_types=1);

use Phinx\Db\Adapter\MysqlAdapter;
use Phinx\Migration\AbstractMigration;

/**
 * Profile pictures — one row per user, bytes and all.
 *
 * **The bytes live in the DB, not on disk**, deliberately. `app_user.avatar_url`
 * has existed since 20260707000001 with a comment saying the file itself is
 * stored "via tds-content-api's existing upload infra (served from /uploads)" —
 * and tds-content-api has since been archived and cut out of the gateway, so
 * that column has pointed at nothing for months and no upload path existed at
 * all. Same reasoning as `cms_legal_doc` in tds-ext-website-cms-pkg: the Plesk
 * host then needs no writable directory, and host-side setup is this platform's
 * chronic go-live blocker. These are a handful of ≤2 MiB images read behind an
 * HTTP cache, not an unbounded customer document store.
 *
 * `user_id` is the PRIMARY KEY rather than an auto-increment id with a unique
 * index: a user has exactly one avatar, and the upload is an upsert. That also
 * makes replacing a picture reuse the row instead of growing the table.
 *
 * MEDIUMBLOB (16 MB) is far above the 2 MiB the upload route enforces; TINYBLOB
 * (255 B) and BLOB (64 KB) are both below a realistic 256×256 JPEG.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthCreateUserAvatar extends AbstractMigration
{
    public function change(): void
    {
        $this->table('app_user_avatar', [
            'id' => false,
            'primary_key' => ['user_id'],
            'signed' => false,
        ])
            // Explicit NOT NULL: MySQL 8 rejects a nullable PRIMARY KEY column
            // (error 1171), whereas MariaDB silently coerces it. Phinx defaults
            // every addColumn() to nullable, so a PK column that doesn't say so
            // itself installs fine on dev/CI MariaDB and kills /install.php on
            // the prod host. Guarded by MigrationDialectTest.
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('mime_type', 'string', ['limit' => 64, 'default' => 'image/webp'])
            ->addColumn('size_bytes', 'integer', ['signed' => false, 'default' => 0])
            ->addColumn('content', 'blob', ['limit' => MysqlAdapter::BLOB_MEDIUM])
            // Doubles as the cache buster in the public URL (`?v=<unix>`) and
            // as the ETag source, so a replaced picture is picked up
            // immediately instead of sitting behind the 5-minute max-age.
            ->addColumn('updated_at', 'datetime', [
                'default' => 'CURRENT_TIMESTAMP',
                'update' => 'CURRENT_TIMESTAMP',
            ])
            ->addForeignKey('user_id', 'app_user', 'id', ['delete' => 'CASCADE'])
            ->create();
    }
}
