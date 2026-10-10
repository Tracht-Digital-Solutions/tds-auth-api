<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * `customers:*` → `companies:*` in the STORED permission arrays.
 *
 * The schema rename (20260814000001) moved the tables and columns; this moves
 * the data that names the Firmen extension's two permissions. They are stored
 * strings — in `app_user_company.permissions`, in `app_user.permissions`, and
 * (from here on) in `auth_group.permissions` — so no amount of renaming
 * elsewhere reaches them.
 *
 * ### Why a targeted REPLACE and not a re-serialise
 *
 * The values are JSON arrays of short slugs. Decoding, mapping and re-encoding
 * every row in PHP would be correct too, but it turns one statement into a
 * cursor over the whole table for a substring that cannot appear anywhere else:
 * `"customers:` only ever begins one of exactly two keys, and the quote makes
 * a partial match (`subcustomers:read`) impossible.
 *
 * The old spelling stays ACCEPTED for one release — `PermissionAliases`
 * normalises it on read — so a token minted before this migration keeps
 * working until it expires. This is the data half of that transition; the
 * follow-up release drops the alias map.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthRenamePermissionKeys extends AbstractMigration
{
    private const RENAMES = [
        '"customers:read"' => '"companies:read"',
        '"customers:write"' => '"companies:write"',
    ];

    public function up(): void
    {
        $conn = $this->getAdapter()->getConnection();
        foreach (['app_user_company' => 'permissions', 'app_user' => 'permissions'] as $table => $column) {
            foreach (self::RENAMES as $from => $to) {
                $this->execute(sprintf(
                    'UPDATE %s SET %s = REPLACE(%s, %s, %s) WHERE %s LIKE %s',
                    $table,
                    $column,
                    $column,
                    $conn->quote($from),
                    $conn->quote($to),
                    $column,
                    $conn->quote("%" . $from . "%"),
                ));
            }
        }
    }

    public function down(): void
    {
        $conn = $this->getAdapter()->getConnection();
        foreach (['app_user_company' => 'permissions', 'app_user' => 'permissions'] as $table => $column) {
            foreach (self::RENAMES as $from => $to) {
                $this->execute(sprintf(
                    'UPDATE %s SET %s = REPLACE(%s, %s, %s) WHERE %s LIKE %s',
                    $table,
                    $column,
                    $column,
                    $conn->quote($to),
                    $conn->quote($from),
                    $column,
                    $conn->quote("%" . $to . "%"),
                ));
            }
        }
    }
}
