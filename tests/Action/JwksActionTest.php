<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\JwksAction;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\Keys;

final class JwksActionTest extends TestCase
{
    public function test_returns_jwks_envelope_with_single_key(): void
    {
        $keys = new Keys();
        $jwt = new JwtService(
            privateKeyPem: $keys->privatePem,
            publicKeyPem: $keys->publicPem,
            keyId: 'unit-kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );

        $request = (new ServerRequestFactory())->createServerRequest('GET', '/.well-known/jwks.json');
        $response = (new JwksAction($jwt))($request, new Response());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('public, max-age=600', $response->getHeaderLine('Cache-Control'));

        $response->getBody()->rewind();
        $body = json_decode($response->getBody()->getContents(), true);
        self::assertIsArray($body);
        self::assertCount(1, $body['keys']);
        self::assertSame('unit-kid', $body['keys'][0]['kid']);
        self::assertSame('RS256', $body['keys'][0]['alg']);
    }
}
