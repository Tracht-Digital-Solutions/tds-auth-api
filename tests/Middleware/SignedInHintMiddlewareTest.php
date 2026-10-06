<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\SignedInHintMiddleware;

final class SignedInHintMiddlewareTest extends TestCase
{
    private function dispatchWith(array $setCookies, string $method = 'POST', string $path = '/login', int $status = 200, array $requestCookies = []): array
    {
        $mw = new SignedInHintMiddleware(['tds_session', 'tds_remember'], 'tds_session', '.tracht-digital.de', true);
        $request = (new ServerRequestFactory())->createServerRequest($method, 'https://api.tracht-digital.de/auth' . $path)
            ->withCookieParams($requestCookies);
        $handler = new class ($setCookies, $status) implements RequestHandlerInterface {
            public function __construct(private array $cookies, private int $status)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = (new Response())->withStatus($this->status);
                foreach ($this->cookies as $line) {
                    $response = $response->withAddedHeader('Set-Cookie', $line);
                }
                return $response;
            }
        };
        return $mw->process($request, $handler)->getHeader('Set-Cookie');
    }

    private function hint(array $headers): ?string
    {
        foreach ($headers as $line) {
            if (str_starts_with($line, 'tds_signed_in=')) {
                return $line;
            }
        }
        return null;
    }

    public function test_login_sets_the_hint_for_the_longest_credential(): void
    {
        $hint = $this->hint($this->dispatchWith([
            'tds_session=abc; Path=/; Max-Age=3600; Domain=.tracht-digital.de; HttpOnly; SameSite=Lax; Secure',
            'tds_remember=xyz; Path=/; Max-Age=2592000; Domain=.tracht-digital.de; HttpOnly; SameSite=Lax; Secure',
        ]));
        self::assertNotNull($hint);
        self::assertStringContainsString('tds_signed_in=1', $hint);
        self::assertStringContainsString('Max-Age=2592000', $hint);
        self::assertStringNotContainsString('HttpOnly', $hint);
        self::assertStringContainsString('Domain=.tracht-digital.de', $hint);
    }

    public function test_logout_expires_the_hint(): void
    {
        $hint = $this->hint($this->dispatchWith([
            'tds_session=; Path=/; Max-Age=0; Domain=.tracht-digital.de; HttpOnly; SameSite=Lax; Secure',
            'tds_remember=; Path=/; Max-Age=0; Domain=.tracht-digital.de; HttpOnly; SameSite=Lax; Secure',
        ], 'POST', '/logout'));
        self::assertNotNull($hint);
        self::assertStringContainsString('tds_signed_in=;', $hint);
        self::assertStringContainsString('Max-Age=0', $hint);
    }

    public function test_an_unrelated_response_leaves_cookies_alone(): void
    {
        $headers = $this->dispatchWith(['tds_passkey_challenge=1; Path=/; Max-Age=300'], 'POST', '/passkey/login/options');
        self::assertNull($this->hint($headers));
    }

    public function test_an_existing_session_gets_the_hint_on_me(): void
    {
        self::assertNotNull($this->hint($this->dispatchWith([], 'GET', '/me')));
        self::assertNull($this->hint($this->dispatchWith([], 'GET', '/me', 200, ['tds_signed_in' => '1'])));
        self::assertNull($this->hint($this->dispatchWith([], 'GET', '/me', 401)));
    }
}
