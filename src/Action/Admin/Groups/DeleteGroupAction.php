<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Groups;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /admin/groups/{id}
 *
 * Deleting a group takes its assignments with it (`auth_user_group` cascades),
 * so it can REMOVE rights from people — which is why the members' sessions are
 * revoked, and why a system group cannot be deleted at all.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class DeleteGroupAction
{
    public function __construct(
        private readonly GroupRepository $groups,
        private readonly SessionRepository $sessions,
    ) {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $id = (int) ($args['id'] ?? 0);
        $group = $id > 0 ? $this->groups->find($id) : null;
        if ($group === null) {
            return $this->json($response, 404, ['error' => 'Group not found']);
        }
        if ($group->isSystem) {
            // The four seeded roles are referenced by slug and are the editor's
            // fallback vocabulary. Their PERMISSIONS stay editable; the row does
            // not go away.
            return $this->json($response, 409, [
                'error' => 'System groups cannot be deleted',
                'code' => 'system_group',
            ]);
        }

        // Collect the members BEFORE the delete cascades their assignments away.
        $memberIds = $this->groups->memberIds($id);

        if (!$this->groups->delete($id)) {
            return $this->json($response, 404, ['error' => 'Group not found']);
        }

        foreach ($memberIds as $userId) {
            $this->sessions->revokeAllForUser($userId);
        }

        return $this->json($response, 200, [
            'ok' => true,
            'sessionsRevoked' => count($memberIds),
        ]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
