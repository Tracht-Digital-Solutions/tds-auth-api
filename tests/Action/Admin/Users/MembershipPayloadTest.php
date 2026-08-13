<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin\Users;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Action\Admin\Users\MembershipPayload;

/**
 * The parser behind `POST/PATCH /admin/users/{id}` company assignment.
 *
 * Everything a portal login can see is decided here: which companies it belongs
 * to, which permissions and groups it holds in each, and whether it administers
 * any of them. The payload arrives from the frontend's user-management editor,
 * so it is untrusted shape — the parser has to drop nonsense rather than write
 * it.
 *
 * The subtle half is {@see MembershipPayload::present()}. An update needs to
 * distinguish "the request said nothing about memberships" (leave them alone)
 * from "the request explicitly cleared them" (revoke every company). Collapsing
 * those two either strands a user with access they should have lost, or wipes
 * the memberships of every user edited for an unrelated reason — which is the
 * bug the `permissions`-alone case used to be.
 *
 * Assertions project the fields under test rather than comparing whole rows:
 * the row grew three keys in this change, and a whole-row comparison would have
 * to be rewritten every time it grows another without testing anything more.
 */
final class MembershipPayloadTest extends TestCase
{
    /** @param list<array<string,mixed>> $out */
    private static function companies(array $out): array
    {
        return array_column($out, 'companyId');
    }

    // --- the modern `memberships` shape -----------------------------------

    public function test_resolves_the_memberships_array(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [
                ['companyId' => 10, 'permissions' => ['projects:read', 'invoices:read']],
                ['companyId' => 20, 'permissions' => ['tickets:read']],
            ],
        ]);

        self::assertSame([10, 20], self::companies($out));
        self::assertSame(['projects:read', 'invoices:read'], $out[0]['permissions']);
        self::assertSame(['tickets:read'], $out[1]['permissions']);
    }

    public function test_accepts_customerId_as_a_deprecated_alias(): void
    {
        // Dual-accept across the rename: a client built before it keeps working
        // for one release.
        $out = MembershipPayload::resolve([
            'memberships' => [['customerId' => 10, 'permissions' => ['tickets:read']]],
        ]);

        self::assertSame([10], self::companies($out));
    }

    public function test_carries_groups_the_company_admin_flag_and_the_ceiling(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [[
                'companyId' => 10,
                'permissions' => ['tickets:read'],
                'groupIds' => [3, 3, 7, 0, -2],
                'isCompanyAdmin' => true,
                'permissionCeiling' => ['tickets:read', 'tickets:write'],
            ]],
        ]);

        self::assertSame([3, 7], $out[0]['groupIds'], 'ids are de-duped and non-positives dropped');
        self::assertTrue($out[0]['isCompanyAdmin']);
        self::assertSame(['tickets:read', 'tickets:write'], $out[0]['permissionCeiling']);
    }

    public function test_an_absent_ceiling_is_null_not_an_empty_list(): void
    {
        // null = inherit the company policy; [] = "may hold nothing". Two
        // different statements, and collapsing them would make locking one
        // user down completely unexpressible.
        $out = MembershipPayload::resolve(['memberships' => [['companyId' => 10]]]);

        self::assertNull($out[0]['permissionCeiling']);

        $explicit = MembershipPayload::resolve([
            'memberships' => [['companyId' => 10, 'permissionCeiling' => []]],
        ]);
        self::assertSame([], $explicit[0]['permissionCeiling']);
    }

    public function test_memberships_wins_over_the_legacy_pair(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [['companyId' => 10, 'permissions' => ['projects:read']]],
            'companyId' => 99,
            'permissions' => ['tickets:write'],
        ]);

        self::assertSame([10], self::companies($out));
        self::assertSame(['projects:read'], $out[0]['permissions']);
    }

    public function test_drops_an_entry_with_a_non_positive_company_id(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [
                ['companyId' => 0, 'permissions' => ['projects:read']],
                ['companyId' => -5, 'permissions' => ['projects:read']],
                ['companyId' => 10, 'permissions' => ['projects:read']],
            ],
        ]);

        self::assertSame([10], self::companies($out));
    }

    public function test_drops_an_entry_with_no_company_id_at_all(): void
    {
        self::assertSame([], MembershipPayload::resolve([
            'memberships' => [['permissions' => ['projects:read']]],
        ]));
    }

    public function test_skips_a_membership_that_is_not_an_object(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => ['nonsense', 42, null, ['companyId' => 10, 'permissions' => []]],
        ]);

        self::assertSame([10], self::companies($out));
    }

    public function test_coerces_a_numeric_string_company_id(): void
    {
        $out = MembershipPayload::resolve(['memberships' => [['companyId' => '10']]]);

        self::assertSame([10], self::companies($out));
    }

    public function test_keeps_an_extension_permission_and_drops_a_malformed_one(): void
    {
        // The catalog check is gone (it silently dropped every composed
        // extension's key); the SHAPE check remains.
        $out = MembershipPayload::resolve([
            'memberships' => [[
                'companyId' => 10,
                'permissions' => ['projects:read', 'companies:write', 'not-a-permission', ''],
            ]],
        ]);

        self::assertSame(['projects:read', 'companies:write'], $out[0]['permissions']);
    }

    public function test_drops_duplicate_permissions(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [['companyId' => 10, 'permissions' => ['projects:read', 'projects:read']]],
        ]);

        self::assertSame(['projects:read'], $out[0]['permissions']);
    }

    public function test_treats_missing_or_non_array_permissions_as_none(): void
    {
        foreach ([['companyId' => 10], ['companyId' => 10, 'permissions' => 'projects:read']] as $entry) {
            $out = MembershipPayload::resolve(['memberships' => [$entry]]);
            self::assertSame([], $out[0]['permissions']);
        }
    }

    public function test_an_explicitly_empty_memberships_array_grants_nothing(): void
    {
        self::assertSame([], MembershipPayload::resolve(['memberships' => []]));
    }

    public function test_ignores_a_memberships_value_that_is_not_an_array(): void
    {
        $out = MembershipPayload::resolve(['memberships' => 'nope', 'companyId' => 10]);

        self::assertSame([10], self::companies($out));
    }

    // --- the legacy single-company shape ----------------------------------

    public function test_falls_back_to_the_legacy_pair(): void
    {
        $out = MembershipPayload::resolve(['companyId' => 10, 'permissions' => ['tickets:read']]);

        self::assertSame([10], self::companies($out));
        self::assertSame(['tickets:read'], $out[0]['permissions']);
    }

    public function test_legacy_null_or_empty_company_id_means_no_company(): void
    {
        foreach ([null, ''] as $value) {
            self::assertSame([], MembershipPayload::resolve(['companyId' => $value]));
        }
    }

    public function test_legacy_non_positive_company_id_means_no_company(): void
    {
        foreach ([0, -1, '0'] as $value) {
            self::assertSame([], MembershipPayload::resolve(['companyId' => $value]));
        }
    }

    public function test_an_empty_payload_yields_no_memberships(): void
    {
        self::assertSame([], MembershipPayload::resolve([]));
    }

    public function test_permissions_without_a_company_are_discarded(): void
    {
        self::assertSame([], MembershipPayload::resolve(['permissions' => ['projects:read']]));
    }

    // --- present(): "silent" vs "explicitly cleared" -----------------------

    public function test_present_is_false_when_the_payload_says_nothing_about_companies(): void
    {
        self::assertFalse(MembershipPayload::present(['name' => 'Erika']));
        self::assertFalse(MembershipPayload::present([]));
    }

    public function test_present_is_TRUE_for_an_explicitly_empty_memberships_array(): void
    {
        self::assertTrue(MembershipPayload::present(['memberships' => []]));
        self::assertSame([], MembershipPayload::resolve(['memberships' => []]));
    }

    public function test_present_is_FALSE_for_permissions_alone(): void
    {
        // The data-loss bug this guards, spelled out: `permissions` alone used
        // to make present() true while resolve() returned [], so a body that
        // never named a company made the caller replace EVERY membership with
        // nothing. A payload that does not mention companies must not be able
        // to remove the user from all of them.
        self::assertFalse(MembershipPayload::present(['permissions' => ['tickets:read']]));
        self::assertSame([], MembershipPayload::resolve(['permissions' => ['tickets:read']]));
    }

    public function test_present_is_true_for_either_company_key(): void
    {
        self::assertTrue(MembershipPayload::present(['companyId' => 10]));
        self::assertTrue(MembershipPayload::present(['customerId' => 10]));
    }

    public function test_present_is_true_even_when_the_value_is_null(): void
    {
        // `companyId: null` is how the editor detaches the single company.
        self::assertTrue(MembershipPayload::present(['companyId' => null]));
    }

    public function test_present_does_not_react_to_unrelated_keys(): void
    {
        self::assertFalse(MembershipPayload::present([
            'email' => 'kunde@example.de',
            'isAdmin' => true,
            'company' => 5,
        ]));
    }
}
