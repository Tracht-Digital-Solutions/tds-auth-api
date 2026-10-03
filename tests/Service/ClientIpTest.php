<?php

declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Tds\AuthApi\Service\ClientIp;

final class ClientIpTest extends TestCase
{
    public function test_takes_the_address_the_gateway_appended_not_the_one_the_client_sent(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/login', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withHeader('X-Forwarded-For', '1.2.3.4, 203.0.113.9');

        self::assertSame('203.0.113.9', ClientIp::from($request));
    }

    public function test_falls_back_to_the_socket_address(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/login', ['REMOTE_ADDR' => '198.51.100.7']);

        self::assertSame('198.51.100.7', ClientIp::from($request));
    }

    public function test_a_forged_value_never_reaches_the_bucket(): void
    {
        // A long or non-address value used to overflow the 100-character
        // bucket column into a 500.
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/login')
            ->withHeader('X-Forwarded-For', str_repeat('x', 300));

        self::assertSame('unknown', ClientIp::from($request));
    }
}
