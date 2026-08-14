<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Domain;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Domain\EffectivePermissions;
use Tds\AuthApi\Domain\Permissions;

/**
 * The rule that decides what a user may actually do:
 * `(direct ∪ groups) \ denies ∩ ceiling`.
 *
 * A pure function, which is the point — the whole authorization model is
 * testable here without a database, a token or a request.
 */
final class EffectivePermissionsTest extends TestCase
{
    public function test_direct_grants_pass_through(): void
    {
        self::assertSame(
            ['tickets:read'],
            EffectivePermissions::resolve(['tickets:read'], []),
        );
    }

    public function test_unions_the_groups_with_the_direct_grants(): void
    {
        $result = EffectivePermissions::resolve(
            ['tickets:read'],
            [['invoices:read'], ['documents:read']],
        );

        self::assertSame(['tickets:read', 'invoices:read', 'documents:read'], $result);
    }

    public function test_dedupes_across_sources(): void
    {
        // The same right from a direct grant and from two groups is one right,
        // not three — and the JWT is size-capped, so duplicates cost something.
        $result = EffectivePermissions::resolve(
            ['tickets:read'],
            [['tickets:read'], ['tickets:read', 'invoices:read']],
        );

        self::assertSame(['tickets:read', 'invoices:read'], $result);
    }

    public function test_the_ceiling_INTERSECTS_rather_than_merely_validating(): void
    {
        // This is what makes a ceiling a ceiling. If it were only checked when
        // granting, lowering it afterwards would leave every already-assigned
        // group out-granting it — a limit that silently stopped applying.
        $result = EffectivePermissions::resolve(
            ['tickets:read', 'invoices:pay'],
            [['documents:write']],
            ['tickets:read', 'documents:write'],
        );

        self::assertSame(['tickets:read', 'documents:write'], $result);
    }

    public function test_a_null_ceiling_means_no_ceiling(): void
    {
        $result = EffectivePermissions::resolve(['tickets:read'], [['invoices:pay']], null);

        self::assertSame(['tickets:read', 'invoices:pay'], $result);
    }

    public function test_an_EMPTY_ceiling_grants_nothing(): void
    {
        // `[]` is a real statement ("may hold nothing"), distinct from null.
        // Collapsing the two would make locking a user down unexpressible.
        self::assertSame(
            [],
            EffectivePermissions::resolve(['tickets:read'], [['invoices:pay']], []),
        );
    }

    public function test_normalises_the_pre_rename_spelling_on_every_side(): void
    {
        // A group seeded before the rename, a direct grant written after it,
        // and a ceiling stored in either spelling must all mean the same right.
        $result = EffectivePermissions::resolve(
            ['customers:read'],
            [['companies:write']],
            ['companies:read', 'customers:write'],
        );

        self::assertSame(['companies:read', 'companies:write'], $result);
    }

    public function test_drops_non_strings_rather_than_crashing(): void
    {
        // Group permissions are JSON out of a database column; a hand-edited
        // row must not take the token issuer down.
        $result = EffectivePermissions::resolve(
            ['tickets:read', '', 'ok:key'],
            [[123, null, 'invoices:read']],
        );

        self::assertSame(['tickets:read', 'ok:key', 'invoices:read'], $result);
    }

    public function test_caps_the_resolved_set(): void
    {
        // The JWT rides in a cookie; an unbounded array is a header-size limit
        // waiting to be hit in production.
        $many = [];
        for ($i = 0; $i < 200; $i++) {
            $many[] = "mod{$i}:read";
        }

        self::assertCount(Permissions::MAX_KEYS, EffectivePermissions::resolve($many, []));
    }

    public function test_there_are_no_deny_rules(): void
    {
        // Grant-only, by design: deny rules make "why can this person not do X"
        // stop having a single answer, and would compete with the ceiling.
        // Nothing in a group set can subtract from the direct grants.
        $result = EffectivePermissions::resolve(['tickets:read'], [[]]);

        self::assertSame(['tickets:read'], $result);
    }
// --- per-person denies -------------------------------------------------

    public function test_a_deny_beats_the_group_that_grants_it(): void
    {
        // The whole point of the feature: one member of a shared group must be
        // able to lose one of its rights without cloning the group for them,
        // which would stop tracking the original from then on.
        $result = EffectivePermissions::resolve(
            [],
            [["invoices:read", "invoices:pay"]],
            null,
            ["invoices:pay"],
        );

        self::assertSame(["invoices:read"], $result);
    }

    public function test_a_deny_beats_a_direct_grant_too(): void
    {
        // Not a special case worth allowing an exception for: "denied" is a
        // statement about the person, not about where the right came from.
        $result = EffectivePermissions::resolve(["tickets:write"], [], null, ["tickets:write"]);

        self::assertSame([], $result);
    }

    public function test_a_deny_for_a_right_nobody_grants_is_inert(): void
    {
        // Denies are stored per person and outlive the group assignment that
        // motivated them. A stale one must not do anything odd.
        $result = EffectivePermissions::resolve(["tickets:read"], [], null, ["wiki:write"]);

        self::assertSame(["tickets:read"], $result);
    }

    public function test_the_ceiling_still_wins_over_everything(): void
    {
        // Order matters for readability, not for the outcome — both the deny
        // and the ceiling only ever subtract. This pins that they compose
        // rather than one of them being skipped when the other applies.
        $result = EffectivePermissions::resolve(
            ["tickets:read", "invoices:pay"],
            [["documents:write"]],
            ["tickets:read", "invoices:pay"],
            ["invoices:pay"],
        );

        self::assertSame(["tickets:read"], $result);
    }

    public function test_a_deny_normalises_the_pre_rename_spelling(): void
    {
        // A deny stored before the customers→companies rename has to withhold
        // the right it names, not a string that no longer matches anything.
        $result = EffectivePermissions::resolve(
            [],
            [["companies:read", "tickets:read"]],
            null,
            ["customers:read"],
        );

        self::assertSame(["tickets:read"], $result);
    }
}
