<?php

declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Build a middleware the first time a route actually runs it.
 *
 * The session gates need the JWT keypair and the database. Constructed while
 * the app was assembled, they made EVERY request — `/healthz`, a CORS
 * preflight, the JWKS document — load the private key and open a DB
 * connection, and an outage threw inside `createApp()` before `/healthz` could
 * report it as `db:down`.
 */
final class LazyMiddleware implements MiddlewareInterface
{
    private ?MiddlewareInterface $inner = null;

    /** @param \Closure(): MiddlewareInterface $factory */
    public function __construct(private readonly \Closure $factory)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $this->inner ??= ($this->factory)();
        return $this->inner->process($request, $handler);
    }
}
