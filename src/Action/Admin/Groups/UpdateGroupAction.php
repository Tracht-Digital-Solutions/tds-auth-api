<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Groups;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PATCH /admin/groups/{id}
 *
 * Body: `{name?, description?, permissions?}`.
 *
 * `slug`, `companyId` and `isSystem` are deliberately not updatable: the slug
 * is referenced, and moving a group between companies would silently change who
 * it grants to. A SYSTEM group's permissions ARE editable — that is what makes
 * the four seeded roles useful — only its identity is locked.
 *
 * ### Editing a group logs its members out
 *
 * Permissions ride in a signed token, so a member's current session keeps the
 * old set until it expires. Revoking their sessions is what makes the edit take
 * effect, and it is the same propagation model every other authorization change
 * here uses. That is also why the response reports how many people it affected.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class UpdateGroupAction
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

        $body = (array) $request->getParsedBody();
        $fields = [];

        if (array_key_exists('name', $body)) {
            $name = trim((string) $body['name']);
            if ($name === '') {
                return $this->json($response, 422, ['error' => 'name must not be empty']);
            }
            $fields['name'] = mb_substr($name, 0, 120);
        }
        if (array_key_exists('description', $body)) {
            $fields['description'] = GroupPayload::description($body['description']);
        }

        $permissionsChanged = array_key_exists('permissions', $body);
        if ($permissionsChanged) {
            $fields['permissions'] = Permissions::sanitize($body['permissions']);
        }

        if ($fields !== []) {
            $this->groups->update($id, $fields);
        }

        // Only a permission change alters what anyone may do; renaming a group
        // must not log 40 people out.
        $affected = 0;
        if ($permissionsChanged) {
            $affected = $this->revokeMembers($id);
        }

        return $this->json($response, 200, [
            'group' => $this->groups->find($id)?->toArray(),
            'sessionsRevoked' => $affected,
        ]);
    }

    private function revokeMembers(int $groupId): int
    {
        $count = 0;
        foreach ($this->groups->memberIds($groupId) as $userId) {
            $this->sessions->revokeAllForUser($userId);
            $count++;
        }

        return $count;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
