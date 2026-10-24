<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\PasskeyRepository;

/**
 * DELETE /passkeys/{id} — remove one of the signed-in user's passkeys.
 *
 * Deletion is scoped to the owner in the SQL predicate, not merely checked
 * beforehand: an id from another account simply matches no row and answers 404.
 * A lost device is exactly when this is used, so it must not depend on anything
 * being reachable except this API.
 */
final class DeleteAction
{
    public function __construct(private readonly PasskeyRepository $passkeys)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response, array $args): ResponseInterface
    {
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $userId = isset($claims['uid']) ? (int) $claims['uid'] : 0;
        $id = (int) ($args['id'] ?? 0);
        if ($userId <= 0) {
            return $this->json($response, 401, ['error' => 'Unknown user']);
        }
        if ($id <= 0) {
            return $this->json($response, 400, ['error' => 'Invalid id']);
        }

        if (!$this->passkeys->deleteForUser($id, $userId)) {
            return $this->json($response, 404, ['error' => 'Not found']);
        }
        return $response->withStatus(204);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
