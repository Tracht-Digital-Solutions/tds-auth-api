<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /admin/login
 *
 * Body: {"token": "..."}
 *
 * Phase-2 bridge: until per-admin credentials exist (Phase 8+), the
 * single shared ADMIN_TOKEN env var unlocks an admin JWT. The JWT is
 * returned in the response body AND set as a cross-subdomain cookie
 * so admin panel pages on admin.tracht-digital.de stay logged in
 * automatically.
 */
final class LoginAction
{
    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $expected = (string) (getenv('ADMIN_TOKEN') ?: '');
        if ($expected === '') {
            return $this->json($response, 500, ['error' => 'ADMIN_TOKEN not configured']);
        }

        // Rate-limit BEFORE checking the token so an attacker can't
        // probe the env-config path to skip the limiter.
        $bucket = 'admin:' . $this->clientIp($request);
        $rl = $this->rateLimiter->check($bucket);
        if (!$rl['allowed']) {
            return $this->json($response, 429, [
                'error' => 'Too many login attempts. Please try again later.',
            ]);
        }

        $body = $request->getParsedBody();
        $candidate = is_array($body) ? (string) ($body['token'] ?? '') : '';

        if ($candidate === '' || !hash_equals($expected, $candidate)) {
            return $this->json($response, 401, ['error' => 'Unauthorized']);
        }

        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $response = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
        ]);
        return $response->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    private function clientIp(ServerRequestInterface $request): string
    {
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if ($forwarded !== '') {
            return trim(explode(',', $forwarded)[0]);
        }
        $real = $request->getHeaderLine('X-Real-IP');
        if ($real !== '') {
            return $real;
        }
        return $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
