<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * What a company is allowed to do on its own — the platform admin's limits on
 * a delegated company admin.
 *
 * **Absent means unlimited.** A company with no policy row behaves exactly as
 * before this feature existed, which is what makes the whole thing opt-in per
 * company rather than a migration everyone has to survive.
 *
 * The three limits are deliberately different shapes:
 * - `maxUsers === null` → no seat cap.
 * - `allowedPermissions === null` → no ceiling at all. An empty ARRAY is a
 *   different statement: "may grant nothing". Collapsing the two would make
 *   "lock this company down completely" unexpressible.
 * - `allowCustomGroups` → may the company admin define groups of their own?
 */
final class CompanyPolicy
{
    /** @param list<string>|null $allowedPermissions */
    public function __construct(
        public readonly int $companyId,
        public readonly ?int $maxUsers = null,
        public readonly ?array $allowedPermissions = null,
        public readonly bool $allowCustomGroups = false,
    ) {
    }

    /** The permissive default for a company nobody has configured. */
    public static function unrestricted(int $companyId): self
    {
        return new self($companyId);
    }

    /**
     * The effective ceiling for one membership: the per-user cap when set,
     * otherwise the company's, otherwise none.
     *
     * @param list<string>|null $userCeiling
     * @return list<string>|null null means "no ceiling"
     */
    public function ceilingFor(?array $userCeiling): ?array
    {
        return $userCeiling ?? $this->allowedPermissions;
    }

    /**
     * The keys in $requested that the ceiling forbids.
     *
     * Returning the rejected set rather than a bool so the API can name them —
     * "Forbidden" without saying which right was refused leaves an admin
     * guessing which checkbox to untick.
     *
     * @param list<string> $requested
     * @param list<string>|null $ceiling
     * @return list<string>
     */
    public static function rejected(array $requested, ?array $ceiling): array
    {
        if ($ceiling === null) {
            return [];
        }
        return array_values(array_filter(
            $requested,
            static fn (string $key): bool => !in_array($key, $ceiling, true),
        ));
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'companyId' => $this->companyId,
            'maxUsers' => $this->maxUsers,
            'allowedPermissions' => $this->allowedPermissions,
            'allowCustomGroups' => $this->allowCustomGroups,
        ];
    }
}
