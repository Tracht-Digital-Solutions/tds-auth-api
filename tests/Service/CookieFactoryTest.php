<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\CookieFactory;

final class CookieFactoryTest extends TestCase
{
    public function test_set_includes_required_attributes(): void
    {
        $cookie = (new CookieFactory('tds_session', '.tracht-digital.de', secure: true))
            ->set('abc.def.ghi', 900);

        self::assertStringStartsWith('tds_session=abc.def.ghi', $cookie);
        self::assertStringContainsString('; Path=/', $cookie);
        self::assertStringContainsString('; Max-Age=900', $cookie);
        self::assertStringContainsString('; Domain=.tracht-digital.de', $cookie);
        self::assertStringContainsString('; HttpOnly', $cookie);
        self::assertStringContainsString('; SameSite=Lax', $cookie);
        self::assertStringContainsString('; Secure', $cookie);
    }

    public function test_set_omits_secure_when_not_secure(): void
    {
        $cookie = (new CookieFactory('tds_session', '.local', secure: false))
            ->set('t', 60);

        self::assertStringNotContainsString('Secure', $cookie);
    }

    public function test_set_url_encodes_token(): void
    {
        $cookie = (new CookieFactory('tds_session', '.local', secure: false))
            ->set('a b/c', 60);

        // rawurlencode: space → %20, / → %2F
        self::assertStringContainsString('tds_session=a%20b%2Fc', $cookie);
    }

    public function test_expire_sets_max_age_zero_and_empty_value(): void
    {
        $cookie = (new CookieFactory('tds_session', '.tracht-digital.de', secure: true))
            ->expire();

        self::assertStringStartsWith('tds_session=;', $cookie);
        self::assertStringContainsString('Max-Age=0', $cookie);
        self::assertStringContainsString('Domain=.tracht-digital.de', $cookie);
        self::assertStringContainsString('Secure', $cookie);
    }

    public function test_name_returns_configured_name(): void
    {
        self::assertSame(
            'foo',
            (new CookieFactory('foo', '.local', secure: false))->name(),
        );
    }
}
