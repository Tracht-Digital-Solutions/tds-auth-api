<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Domain\Membership;

/**
 * The rules a company admin's writes must obey.
 *
 * Collected here rather than repeated in four actions: each one is a boundary
 * that has to hold on **every** route, and a guard that exists in three of four
 * places is not a guard.
 *
 * Each method returns `null` when the write is allowed, or `[status, payload]`
 * when it is not — so an action reads as a list of gates rather than nested
 * conditionals.
 */
final class CompanyUserGuard
{
    /**
     * Fields a company-scoped payload may carry. Anything else is REJECTED,
     * not ignored.
     *
     * Rejecting loudly is the point: silently dropping `isAdmin` means a
     * broken client (or someone probing) gets a 200 and believes it worked.
     * `permissionCeiling` is absent on purpose — it is the platform admin's
     * limit on this company, so a company admin raising their own would be the
     * whole feature defeated. `permissionDenies` IS allowed for the mirror
     * reason: a deny can only ever reduce, so it needs no ceiling check and
     * grants a company admin nothing they did not already have.
     */
    private const ALLOWED_FIELDS = [
        'email', 'name', 'displayName', 'status',
        'permissions', 'groupIds', 'isCompanyAdmin', 'permissionDenies',
    ];

    /**
     * The target must be a member of THIS company.
     *
     * **404, not 403.** A 403 would confirm that the account exists — turning
     * the route into an existence oracle for other companies' users, which a
     * company admin has no business learning.
     *
     * @return array{int, array<string,mixed>}|null
     */
    public static function targetInCompany(?AppUser $target, int $companyId): ?array
    {
        if ($target === null) {
            return [404, ['error' => 'User not found']];
        }
        foreach ($target->memberships as $membership) {
            if ($membership->companyId === $companyId) {
                return null;
            }
        }

        return [404, ['error' => 'User not found']];
    }

    /**
     * A platform admin is never manageable from a company route.
     *
     * Without this, a company admin could disable the account that administers
     * the platform — or, with a wide enough ceiling, grant themselves through
     * an account that bypasses ceilings entirely.
     *
     * @return array{int, array<string,mixed>}|null
     */
    public static function notPlatformAdmin(AppUser $target): ?array
    {
        return $target->isAdmin
            ? [403, ['error' => 'Platform administrators cannot be managed here']]
            : null;
    }

    /**
     * Only the whitelisted fields, and say which one was refused.
     *
     * @param array<string,mixed> $body
     * @return array{int, array<string,mixed>}|null
     */
    public static function fields(array $body): ?array
    {
        $unknown = array_values(array_diff(array_keys($body), self::ALLOWED_FIELDS));
        if ($unknown === []) {
            return null;
        }

        return [422, [
            'error' => 'Field not allowed here',
            'code' => 'field_not_allowed',
            'fields' => $unknown,
        ]];
    }

    /**
     * Nothing may be granted beyond the ceiling — and that includes what the
     * assigned GROUPS carry.
     *
     * Checking only the direct grants would leave the obvious hole: assign a
     * platform group that contains a forbidden key and the ceiling is bypassed
     * without ever naming the key.
     *
     * @param list<string> $direct
     * @param list<list<string>> $groupSets
     * @param list<string>|null $ceiling
     * @return array{int, array<string,mixed>}|null
     */
    public static function withinCeiling(array $direct, array $groupSets, ?array $ceiling): ?array
    {
        if ($ceiling === null) {
            return null;
        }

        $requested = $direct;
        foreach ($groupSets as $set) {
            foreach ($set as $key) {
                if (!in_array($key, $requested, true)) {
                    $requested[] = $key;
                }
            }
        }

        $rejected = CompanyPolicy::rejected($requested, $ceiling);
        if ($rejected === []) {
            return null;
        }

        // Name the rejected keys: "Forbidden" alone leaves an admin guessing
        // which checkbox to untick.
        return [422, [
            'error' => 'Permission not allowed for this company',
            'code' => 'permission_not_allowed',
            'rejected' => $rejected,
        ]];
    }

    /**
     * A company must keep at least one admin.
     *
     * Mirrors the platform's own self-lockout guard: without it, the last
     * company admin can quietly remove the only account that could ever
     * restore access, and only a platform admin can undo it.
     *
     * @return array{int, array<string,mixed>}|null
     */
    public static function notLastCompanyAdmin(
        AppUser $target,
        int $companyId,
        int $adminCount,
        bool $stillAdminAfterwards,
    ): ?array {
        if ($stillAdminAfterwards || $adminCount > 1) {
            return null;
        }

        foreach ($target->memberships as $membership) {
            if ($membership->companyId === $companyId && $membership->isCompanyAdmin) {
                return [409, [
                    'error' => 'The company would be left without an administrator',
                    'code' => 'last_company_admin',
                ]];
            }
        }

        return null;
    }

    /** The membership of $companyId, or null. */
    public static function membership(AppUser $user, int $companyId): ?Membership
    {
        foreach ($user->memberships as $membership) {
            if ($membership->companyId === $companyId) {
                return $membership;
            }
        }

        return null;
    }
}
