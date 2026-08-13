<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * The one-release bridge across the `customer` → `company` rename.
 *
 * Permission keys are **stored data**: they sit in `app_user_company.permissions`,
 * in `auth_group.permissions`, and they ride in the JWT. Renaming them is
 * therefore not a search-and-replace over source — a token minted five minutes
 * before the deploy still carries the old spelling for up to an hour, and a
 * client built against the old names may still be sending them.
 *
 * So both spellings are ACCEPTED and normalised to the new one on the way in
 * (`Permissions::sanitize`, `Permissions::hydrate`), while everything written
 * out uses the new one. Migration `20260814000007` rewrites the rows that
 * already exist; this handles the traffic in flight.
 *
 * **This map is deleted in the follow-up release.** It exists to make the
 * transition invisible, not to keep two vocabularies alive: leaving it in place
 * means the old id keeps working forever and the rename was for nothing.
 */
final class PermissionAliases
{
    /**
     * Legacy key → current key.
     *
     * Only the Firmen extension's two keys were renamed. Every other
     * permission id was already neutral (`tickets:read`, `time:write`, …).
     *
     * @var array<string, string>
     */
    private const MAP = [
        'customers:read' => 'companies:read',
        'customers:write' => 'companies:write',
    ];

    /** The current spelling of $key (unchanged when it has no alias). */
    public static function canonical(string $key): string
    {
        return self::MAP[$key] ?? $key;
    }

    /**
     * Both spellings of $key, for a caller that has to MATCH against stored
     * data it did not normalise — the `/wiki.json` route docs, say, or a
     * permission check running against a token issued before the rename.
     *
     * @return list<string>
     */
    public static function accepted(string $key): array
    {
        $canonical = self::canonical($key);
        $legacy = array_search($canonical, self::MAP, true);

        return $legacy === false ? [$canonical] : [$canonical, $legacy];
    }
}
