<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\JwtService;

/**
 * GET /.well-known/jwks.json
 *
 * Publishes the public key so other services (tds-content-api,
 * tds-customer-api, etc.) can verify JWTs without ever seeing the
 * private key. Cacheable for 10 minutes — keys rotate rarely; if
 * urgent rotation is needed, also bust the consuming services'
 * caches.
 */
final class JwksAction
{
    public function __construct(private readonly JwtService $jwt)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $response->getBody()->write(json_encode([
            'keys' => [$this->jwt->jwk()],
        ]));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'public, max-age=600');
    }
}
