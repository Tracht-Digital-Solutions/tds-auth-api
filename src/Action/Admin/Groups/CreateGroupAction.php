<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Groups;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\GroupRepository;

/**
 * POST /admin/groups
 *
 * Body: `{slug, name, description?, permissions[], companyId?}`.
 *
 * `companyId` omitted (or 0) creates a PLATFORM group, assignable in every
 * company. Passing one creates a group owned by that company — the same row
 * shape a company admin creates through `/company/{id}/groups`, so there is one
 * concept rather than two.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class CreateGroupAction
{
    public function __construct(private readonly GroupRepository $groups)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $body = (array) $request->getParsedBody();

        $companyId = max(0, (int) ($body['companyId'] ?? $body['customerId'] ?? Group::PLATFORM));
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

        $id = $this->groups->create(
            $companyId,
            $slug,
            mb_substr($name, 0, 120),
            GroupPayload::description($body['description'] ?? null),
            Permissions::sanitize($body['permissions'] ?? []),
        );

        return $this->json($response, 201, ['group' => $this->groups->find($id)?->toArray()]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
