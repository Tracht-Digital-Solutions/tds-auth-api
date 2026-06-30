<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Domain;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Domain\Permissions;

final class PermissionsTest extends TestCase
{
    public function test_sanitize_drops_unknown_keys(): void
    {
        $result = Permissions::sanitize(['invoices:pay', 'invoices:delete', 'projects:read']);

        self::assertSame(['projects:read', 'invoices:pay'], $result);
    }

    public function test_sanitize_dedupes_and_orders_by_catalog(): void
    {
        $result = Permissions::sanitize(['messages:write', 'projects:read', 'projects:read']);

        self::assertSame(['projects:read', 'messages:write'], $result);
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
