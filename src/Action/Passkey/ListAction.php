<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\PasskeyRepository;

/**
 * GET /passkeys — the signed-in user's own registered passkeys.
 *
 * Scoped to the JWT's `uid`; there is no way to ask for someone else's, and the
 * credential id is returned only so the UI can key rows, never the public key.
 */
final class ListAction
{
    public function __construct(private readonly PasskeyRepository $passkeys)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $userId = isset($claims['uid']) ? (int) $claims['uid'] : 0;
        if ($userId <= 0) {
            $response->getBody()->write(json_encode(['error' => 'Unknown user']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $response->getBody()->write(json_encode(
            ['passkeys' => $this->passkeys->listForUser($userId)],
            JSON_THROW_ON_ERROR,
        ));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
