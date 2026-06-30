<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * Portal permission catalog (PHP side). Hand-duplicated from
 * `PORTAL_PERMISSIONS` in @tracht-digital-solutions/tds-shared — keep the two
 * in sync. Admin-panel access is the separate `is_admin` flag, not a key here.
 */
final class Permissions
{
    /** @var list<string> */
    public const ALL = [
        'projects:read',
        'invoices:read',
        'invoices:pay',
        'documents:read',
        'documents:write',
        'documents:sign',
        'messages:read',
        'messages:write',
    ];

    /**
     * Coerce arbitrary input into a clean list of known permission keys
     * (drops unknowns + duplicates, preserves catalog order).
     *
     * @return list<string>
     */
    public static function sanitize(mixed $input): array
    {
        if (!is_array($input)) {
            return [];
        }
        $asStrings = array_map(static fn ($v) => (string) $v, $input);
        return array_values(array_intersect(self::ALL, $asStrings));
    }
}
