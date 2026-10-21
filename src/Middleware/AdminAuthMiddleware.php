<?php
declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

/**
 * Bearer-token gate for admin-only endpoints. Constant-time comparison
 * against ADMIN_TOKEN env. Used for cross-service admin calls — e.g.
 * tds-customer-api invoking POST /admin/customer-credentials during
 * customer onboarding.
 */
final class AdminAuthMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly string $expectedToken)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->expectedToken === '') {
            return $this->unauthorized('admin token not configured');
        }

        $auth = $request->getHeaderLine('Authorization');
        if ($auth === '' || preg_match('/^Bearer\s+(.+)$/i', $auth, $m) !== 1) {
            return $this->unauthorized();
        }
        if (!hash_equals($this->expectedToken, $m[1])) {
            return $this->unauthorized();
        }

        return $handler->handle($request);
    }

    private function unauthorized(string $detail = 'unauthorized'): ResponseInterface
    {
        $r = new Response(401);
        $r->getBody()->write(json_encode(['error' => $detail]));
        return $r->withHeader('Content-Type', 'application/json');
    }
}
