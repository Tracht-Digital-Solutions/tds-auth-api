<?php
declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * Gate for customer-only endpoints. Accepts a customer JWT from the
 * Authorization: Bearer header or the session cookie, verifies the
 * signature, rejects admin / non-customer tokens, and confirms the
 * session hasn't been revoked.
 *
 * On success it stashes the authenticated principal on the request as
 * the `customer_id` (int) and `jti` (string) attributes, so downstream
 * actions stay auth-agnostic and never re-derive identity themselves.
 */
final class CustomerAuthMiddleware implements MiddlewareInterface
{
    public const ATTR_CUSTOMER_ID = 'customer_id';
    public const ATTR_JTI = 'jti';

    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
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
        $customerId = isset($claims['customer_id']) && is_int($claims['customer_id']) ? $claims['customer_id'] : null;
        $admin = (bool) ($claims['admin'] ?? false);

        if ($admin || $customerId === null || $jti === '') {
            return $this->error(403, 'Customer session required');
        }
        if ($this->sessions->isRevoked($jti)) {
            return $this->error(401, 'Session revoked');
        }

        $request = $request
            ->withAttribute(self::ATTR_CUSTOMER_ID, $customerId)
            ->withAttribute(self::ATTR_JTI, $jti);

        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && preg_match('/^Bearer\s+(.+)$/i', $auth, $m) === 1) {
            return $m[1];
        }
        $cookie = $request->getCookieParams()[$this->cookies->name()] ?? null;
        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    private function error(int $status, string $message): ResponseInterface
    {
        $r = new Response($status);
        $r->getBody()->write(json_encode(['error' => $message]));
        return $r->withHeader('Content-Type', 'application/json');
    }
}
