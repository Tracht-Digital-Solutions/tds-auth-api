<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
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
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $expected = (string) (getenv('ADMIN_TOKEN') ?: '');
        if ($expected === '') {
            return $this->json($response, 500, ['error' => 'ADMIN_TOKEN not configured']);
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

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
