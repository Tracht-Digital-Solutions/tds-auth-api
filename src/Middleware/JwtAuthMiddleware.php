<?php
declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * Session gate for first-party endpoints. Accepts a JWT from the
 * Authorization: Bearer header or the session cookie, verifies the signature
 * locally (this service holds the keypair), and confirms the session row
 * hasn't been revoked. On success it attaches the decoded claims as the
 * `claims` request attribute.
 *
 * With `requireAdmin: true` it additionally rejects non-admin tokens with 403
 * — this is the per-admin replacement for the shared ADMIN_TOKEN gate on the
 * user-management + session endpoints.
 */
final class JwtAuthMiddleware implements MiddlewareInterface
{
    public const COOKIE_NAME = 'tds_session';
    public const ATTR_CLAIMS = 'claims';

    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly bool $requireAdmin = false,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            return $this->error(401, 'No token presented');
        }

        try {
            $claims = $this->jwt->verify($token);
        } catch (\Throwable) {
            return $this->error(401, 'Invalid token');
        }

        $jti = (string) ($claims['jti'] ?? '');
        if ($jti === '' || $this->sessions->isRevoked($jti)) {
            return $this->error(401, 'Session revoked');
        }

        if ($this->requireAdmin && (bool) ($claims['admin'] ?? false) !== true) {
            return $this->error(403, 'Admin access required');
        }

        $request = $request->withAttribute(self::ATTR_CLAIMS, $claims);
        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && preg_match('/^Bearer\s+(.+)$/i', $auth, $m) === 1) {
            return $m[1];
        }
        $cookie = $request->getCookieParams()[self::COOKIE_NAME] ?? null;
        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    private function error(int $status, string $message): ResponseInterface
    {
        $r = new Response($status);
        $r->getBody()->write(json_encode(['error' => $message]));
        return $r->withHeader('Content-Type', 'application/json');
    }
}
