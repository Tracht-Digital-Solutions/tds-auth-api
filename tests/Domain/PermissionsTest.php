<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Domain;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Domain\Permissions;

final class PermissionsTest extends TestCase
{
    public function test_sanitize_keeps_a_key_the_seed_set_does_not_contain(): void
    {
        // Deliberately reversed. This used to intersect with the nine portal
        // keys — on write AND on read — so every one of the thirteen composed
        // extensions' permissions was accepted by the UI, written to the
        // database and silently dropped again on load. The catalog belongs to
        // the service that ENFORCES it; here only the shape is checked, and an
        // unrecognised key grants nothing anywhere.
        $result = Permissions::sanitize(['invoices:pay', 'invoices:delete', 'companies:write']);

        self::assertSame(['invoices:pay', 'invoices:delete', 'companies:write'], $result);
    }

    public function test_sanitize_drops_MALFORMED_keys(): void
    {
        $result = Permissions::sanitize([
            'projects:read',
            'nocolon',
            'Upper:Case',
            'trailing:',
            ':leading',
            'spaced key:read',
            '*',
            'tickets:*',
            ['nested'],
        ]);

        self::assertSame(['projects:read'], $result);
    }

    public function test_sanitize_dedupes_and_keeps_INPUT_order(): void
    {
        // Order is the caller's, not the catalog's. The old implementation
        // returned `array_intersect(self::ALL, …)`, which silently re-sorted
        // every array into catalog sequence; nothing depended on it, but this
        // pins the new behaviour so nobody restores the intersection while
        // believing they are fixing a sort.
        $result = Permissions::sanitize(['messages:write', 'projects:read', 'projects:read']);

        self::assertSame(['messages:write', 'projects:read'], $result);
    }

    public function test_sanitize_normalises_the_pre_rename_spelling(): void
    {
        // `customers:*` is what the Firmen extension's rights were called
        // before the rename; a payload from a client built against the old
        // names must land as the same right, not a second one.
        self::assertSame(
            ['companies:read', 'companies:write'],
            Permissions::sanitize(['customers:read', 'companies:write']),
        );
    }

    public function test_sanitize_caps_the_number_of_keys(): void
    {
        // The resolved set rides in the JWT, which rides in a cookie.
        $many = [];
        for ($i = 0; $i < 200; $i++) {
            $many[] = "mod{$i}:read";
        }

        self::assertCount(Permissions::MAX_KEYS, Permissions::sanitize($many));
    }

    public function test_hydrate_does_NOT_filter(): void
    {
        // Reading must never rewrite what the database says. Filtering on read
        // is exactly how a legitimately granted key vanished from a token
        // without any write ever having happened.
        self::assertSame(
            ['invoices:delete', 'anything:goes'],
            Permissions::hydrate('["invoices:delete","anything:goes"]'),
        );
    }

    public function test_sanitize_handles_non_array(): void
    {
        self::assertSame([], Permissions::sanitize('nonsense'));
        self::assertSame([], Permissions::sanitize(null));
    }

    public function test_catalog_has_no_duplicates(): void
    {
        self::assertSame(Permissions::ALL, array_values(array_unique(Permissions::ALL)));
    }
}
