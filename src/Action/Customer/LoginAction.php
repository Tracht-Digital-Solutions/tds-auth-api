<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Customer;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;

/**
 * POST /customer/login — STUB.
 *
 * Phase 4 ships this stub to give the auth API a stable URL surface.
 * Phase 8 fills it in: the customer_credential table is created in
 * tds-customer-api's migrations, and this action verifies the
 * email + password (argon2id) and issues a customer JWT.
 *
 * Until then, this returns 501.
 */
final class LoginAction
{
    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $response->getBody()->write(json_encode([
            'error' => 'Not implemented yet — customer login is delivered in Phase 8.',
        ]));
        return $response->withStatus(501)->withHeader('Content-Type', 'application/json');
    }
}
