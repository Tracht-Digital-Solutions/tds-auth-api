<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /admin/users/{id}
 *
 * Deletes a user and revokes all their sessions. The acting admin cannot
 * delete themselves. Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class DeleteUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly SessionRepository $sessions,
    ) {
    }

    /** @param array<string,string> $args */
    public function __invoke(ServerRequestInterface $request, Response $response, array $args): ResponseInterface
    {
        $id = (int) ($args['id'] ?? 0);

        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $actingUid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        if ($id === $actingUid) {
            $response->getBody()->write(json_encode(['error' => 'Cannot delete your own account']));
            return $response->withStatus(409)->withHeader('Content-Type', 'application/json');
        }

        $this->sessions->revokeAllForUser($id);
        $deleted = $this->users->delete($id);

        if (!$deleted) {
            $response->getBody()->write(json_encode(['error' => 'User not found']));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        return $response->withStatus(204);
    }
}
