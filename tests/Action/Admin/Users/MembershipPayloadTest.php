<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin\Users;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Action\Admin\Users\MembershipPayload;

/**
 * The parser behind `POST/PATCH /admin/users/{id}` company assignment.
 *
 * Everything a portal login can see is decided here: which companies it belongs
 * to and which permissions it holds in each. The payload arrives from the
 * frontend's user-management editor, so it is untrusted shape — the parser has
 * to drop nonsense rather than write it.
 *
 * The subtle half is {@see MembershipPayload::present()}. An update needs to
 * distinguish "the request said nothing about memberships" (leave them alone)
 * from "the request explicitly cleared them" (revoke every company). Collapsing
 * those two either strands a user with access they should have lost, or wipes
 * the memberships of every user edited for an unrelated reason.
 */
final class MembershipPayloadTest extends TestCase
{
    // --- the modern `memberships` shape -----------------------------------

    public function test_resolves_the_memberships_array(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [
                ['customerId' => 10, 'permissions' => ['projects:read', 'invoices:read']],
                ['customerId' => 20, 'permissions' => ['tickets:read']],
            ],
        ]);

        self::assertSame([
            ['customerId' => 10, 'permissions' => ['projects:read', 'invoices:read']],
            ['customerId' => 20, 'permissions' => ['tickets:read']],
        ], $out);
    }

    public function test_memberships_wins_over_the_legacy_pair(): void
    {
        // Both shapes present: the editor sends `memberships`, and a stale
        // `customerId` must not quietly override it with a single company.
        $out = MembershipPayload::resolve([
            'memberships' => [['customerId' => 10, 'permissions' => ['projects:read']]],
            'customerId' => 99,
            'permissions' => ['tickets:write'],
        ]);

        self::assertSame([['customerId' => 10, 'permissions' => ['projects:read']]], $out);
    }

    public function test_drops_an_entry_with_a_non_positive_customer_id(): void
    {
        // customerId 0 would attach the login to a company that cannot exist.
        $out = MembershipPayload::resolve([
            'memberships' => [
                ['customerId' => 0, 'permissions' => ['projects:read']],
                ['customerId' => -5, 'permissions' => ['projects:read']],
                ['customerId' => 10, 'permissions' => ['projects:read']],
            ],
        ]);

        self::assertSame([['customerId' => 10, 'permissions' => ['projects:read']]], $out);
    }

    public function test_drops_an_entry_with_no_customer_id_at_all(): void
    {
        $out = MembershipPayload::resolve(['memberships' => [['permissions' => ['projects:read']]]]);
        self::assertSame([], $out);
    }

    public function test_skips_a_membership_that_is_not_an_object(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => ['nonsense', 42, null, ['customerId' => 10, 'permissions' => []]],
        ]);
        self::assertSame([['customerId' => 10, 'permissions' => []]], $out);
    }

    public function test_coerces_a_numeric_string_customer_id(): void
    {
        // JSON from a form field arrives as a string often enough to matter.
        $out = MembershipPayload::resolve(['memberships' => [['customerId' => '10', 'permissions' => []]]]);
        self::assertSame([['customerId' => 10, 'permissions' => []]], $out);
    }

    public function test_SANITISES_unknown_permission_keys(): void
    {
        // An unknown key written to the DB rides the JWT and is compared
        // verbatim by every consumer — it must never reach storage.
        $out = MembershipPayload::resolve([
            'memberships' => [[
                'customerId' => 10,
                'permissions' => ['projects:read', 'admin:everything', 'not-a-permission', ''],
            ]],
        ]);

        self::assertSame([['customerId' => 10, 'permissions' => ['projects:read']]], $out);
    }

    public function test_drops_duplicate_permissions(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [['customerId' => 10, 'permissions' => ['projects:read', 'projects:read']]],
        ]);
        self::assertSame([['customerId' => 10, 'permissions' => ['projects:read']]], $out);
    }

    public function test_treats_missing_permissions_as_none(): void
    {
        // A membership with no rights is legitimate; it must not inherit any.
        $out = MembershipPayload::resolve(['memberships' => [['customerId' => 10]]]);
        self::assertSame([['customerId' => 10, 'permissions' => []]], $out);
    }

    public function test_treats_a_non_array_permissions_value_as_none(): void
    {
        $out = MembershipPayload::resolve([
            'memberships' => [['customerId' => 10, 'permissions' => 'projects:read']],
        ]);
        self::assertSame([['customerId' => 10, 'permissions' => []]], $out);
    }

    public function test_an_explicitly_empty_memberships_array_grants_nothing(): void
    {
        self::assertSame([], MembershipPayload::resolve(['memberships' => []]));
    }

    public function test_ignores_a_memberships_value_that_is_not_an_array(): void
    {
        // Falls through to the legacy branch rather than crashing.
        $out = MembershipPayload::resolve(['memberships' => 'nope', 'customerId' => 10]);
        self::assertSame([['customerId' => 10, 'permissions' => []]], $out);
    }

    // --- the legacy single-company shape ----------------------------------

    public function test_falls_back_to_the_legacy_pair(): void
    {
        $out = MembershipPayload::resolve(['customerId' => 10, 'permissions' => ['tickets:read']]);
        self::assertSame([['customerId' => 10, 'permissions' => ['tickets:read']]], $out);
    }

    public function test_legacy_null_or_empty_customer_id_means_no_company(): void
    {
        foreach ([null, ''] as $value) {
            self::assertSame([], MembershipPayload::resolve(['customerId' => $value]));
        }
    }

    public function test_legacy_non_positive_customer_id_means_no_company(): void
    {
        foreach ([0, -1, '0'] as $value) {
            self::assertSame([], MembershipPayload::resolve(['customerId' => $value]));
        }
    }

    public function test_legacy_sanitises_its_permissions_too(): void
    {
        $out = MembershipPayload::resolve([
            'customerId' => 10,
            'permissions' => ['tickets:read', 'admin:everything'],
        ]);
        self::assertSame([['customerId' => 10, 'permissions' => ['tickets:read']]], $out);
    }

    public function test_an_empty_payload_yields_no_memberships(): void
    {
        self::assertSame([], MembershipPayload::resolve([]));
    }

    public function test_permissions_without_a_company_are_discarded(): void
    {
        // Rights are only meaningful scoped to a company.
        self::assertSame([], MembershipPayload::resolve(['permissions' => ['projects:read']]));
    }

    // --- present(): "silent" vs "explicitly cleared" -----------------------

    public function test_present_is_false_when_the_payload_says_nothing_about_companies(): void
    {
        // An update that only renames a user must leave its memberships alone.
        self::assertFalse(MembershipPayload::present(['name' => 'Erika']));
        self::assertFalse(MembershipPayload::present([]));
    }

    public function test_present_is_TRUE_for_an_explicitly_empty_memberships_array(): void
    {
        // This is the "revoke every company" request. Reading it as "said
        // nothing" would leave the user with access an admin just removed.
        self::assertTrue(MembershipPayload::present(['memberships' => []]));
        self::assertSame([], MembershipPayload::resolve(['memberships' => []]));
    }

    public function test_present_is_true_for_the_legacy_keys(): void
    {
        self::assertTrue(MembershipPayload::present(['customerId' => 10]));
        self::assertTrue(MembershipPayload::present(['permissions' => []]));
    }

    public function test_present_is_true_even_when_the_value_is_null(): void
    {
        // `customerId: null` is how the editor detaches the single company.
        self::assertTrue(MembershipPayload::present(['customerId' => null]));
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
