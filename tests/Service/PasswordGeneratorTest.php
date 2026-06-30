<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\PasswordGenerator;

final class PasswordGeneratorTest extends TestCase
{
    public function test_default_length_is_at_least_16(): void
    {
        self::assertSame(16, strlen((new PasswordGenerator())->generate()));
    }

    public function test_enforces_minimum_length(): void
    {
        self::assertSame(12, strlen((new PasswordGenerator())->generate(4)));
    }

    public function test_generates_distinct_values(): void
    {
        $gen = new PasswordGenerator();
        self::assertNotSame($gen->generate(), $gen->generate());
    }

    public function test_uses_url_safe_alphabet(): void
    {
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]+$/', (new PasswordGenerator())->generate(32));
    }
}
