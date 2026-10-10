<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\Groups\GroupPayload;
use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * `POST|PATCH|DELETE /company/{companyId}/groups[/{id}]`
 *
 * A company admin defining roles for their own company — gated by the platform
 * admin's `allow_custom_groups`, and capped by the same ceiling that limits
 * what they may grant directly. Without that cap, custom groups would be a
 * trivial way around the ceiling: put the forbidden right in a group, assign
 * the group.
 *
 * One action for the three verbs because they share every guard and differ only
 * in the last two lines; splitting them would triplicate the interesting part
 * and leave three places for a check to go missing.
 *
 * A company admin can only ever touch groups **owned by their company**:
 * platform groups are assignable here but not editable, or one company could
 * rewrite a role every other company uses.
 *
 * Gated by JwtAuthMiddleware + CompanyAdminMiddleware.
 */
final class CompanyGroupAction
{
    public function __construct(
        private readonly GroupRepository $groups,
        private readonly CompanyPolicyRepository $policies,
        private readonly SessionRepository $sessions,
    ) {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $companyId = (int) $request->getAttribute(CompanyAdminMiddleware::ATTR_COMPANY_ID, 0);
        $policy = $this->policies->get($companyId);

        if (!$policy->allowCustomGroups) {
            return $this->json($response, 403, [
                'error' => 'This company may not define its own groups',
                'code' => 'custom_groups_disabled',
            ]);
        }

        $method = strtoupper($request->getMethod());
        $id = isset($args['id']) ? (int) $args['id'] : 0;

        return match ($method) {
            'POST' => $this->create($request, $response, $companyId, $policy),
            'PATCH' => $this->update($request, $response, $companyId, $policy, $id),
            'DELETE' => $this->delete($response, $companyId, $id),
            default => $this->json($response, 405, ['error' => 'Method not allowed']),
        };
    }

    private function create(
        ServerRequestInterface $request,
        Response $response,
        int $companyId,
        CompanyPolicy $policy,
    ): ResponseInterface {
        $body = (array) $request->getParsedBody();

        $name = trim((string) ($body['name'] ?? ''));
        if ($name === '') {
            return $this->json($response, 422, ['error' => 'name is required']);
        }

        $slug = GroupPayload::slug($body['slug'] ?? $name);
        if ($slug === '') {
            return $this->json($response, 422, ['error' => 'slug must contain at least one letter or digit']);
        }
        if ($this->groups->slugExists($slug, $companyId)) {
            return $this->json($response, 409, ['error' => 'A group with that slug already exists here']);
        }

        $permissions = Permissions::sanitize($body['permissions'] ?? []);
        if (($deny = $this->withinCeiling($permissions, $policy)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $id = $this->groups->create(
            $companyId,
            $slug,
            mb_substr($name, 0, 120),
            GroupPayload::description($body['description'] ?? null),
            $permissions,
        );

        return $this->json($response, 201, ['group' => $this->groups->find($id)?->toArray()]);
    }

    private function update(
        ServerRequestInterface $request,
        Response $response,
        int $companyId,
        CompanyPolicy $policy,
        int $id,
    ): ResponseInterface {
        $group = $this->owned($id, $companyId);
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
            $permissions = Permissions::sanitize($body['permissions']);
            if (($deny = $this->withinCeiling($permissions, $policy)) !== null) {
                return $this->json($response, $deny[0], $deny[1]);
            }
            $fields['permissions'] = $permissions;
        }

        if ($fields !== []) {
            $this->groups->update($id, $fields);
        }

        // Renaming must not log anyone out; changing what the group GRANTS must.
        $revoked = 0;
        if ($permissionsChanged) {
            foreach ($this->groups->memberIds($id) as $userId) {
                $this->sessions->revokeAllForUser($userId);
                $revoked++;
            }
        }

        return $this->json($response, 200, [
            'group' => $this->groups->find($id)?->toArray(),
            'sessionsRevoked' => $revoked,
        ]);
    }

    private function delete(Response $response, int $companyId, int $id): ResponseInterface
    {
        $group = $this->owned($id, $companyId);
        if ($group === null) {
            return $this->json($response, 404, ['error' => 'Group not found']);
        }

        $memberIds = $this->groups->memberIds($id);
        if (!$this->groups->delete($id)) {
            return $this->json($response, 404, ['error' => 'Group not found']);
        }

        foreach ($memberIds as $userId) {
            $this->sessions->revokeAllForUser($userId);
        }

        return $this->json($response, 200, ['ok' => true, 'sessionsRevoked' => count($memberIds)]);
    }

    /**
     * The group, only if this company OWNS it.
     *
     * A platform group is assignable here but not editable — otherwise one
     * company could rewrite a role every other company relies on. Returns null
     * (→ 404) rather than 403 for a platform group too: which groups exist
     * outside this company is not this admin's business.
     */
    private function owned(int $id, int $companyId): ?Group
    {
        $group = $id > 0 ? $this->groups->find($id) : null;

        return $group !== null && $group->companyId === $companyId && !$group->isSystem
            ? $group
            : null;
    }

    /**
     * @param list<string> $permissions
     * @return array{int, array<string,mixed>}|null
     */
    private function withinCeiling(array $permissions, CompanyPolicy $policy): ?array
    {
        $rejected = CompanyPolicy::rejected($permissions, $policy->allowedPermissions);
        if ($rejected === []) {
            return null;
        }

        return [422, [
            'error' => 'Permission not allowed for this company',
            'code' => 'permission_not_allowed',
            'rejected' => $rejected,
        ]];
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
