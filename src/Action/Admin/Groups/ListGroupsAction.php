<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Groups;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Service\GroupRepository;

/**
 * GET /admin/groups[?company_id=N]
 *
 * Every group, or the ones visible in one company (its own plus the platform's).
 * `memberCount` rides along so the editor can warn before an edit that changes
 * what a set of people can do — a group with 40 members is not the same edit as
 * one with none.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class ListGroupsAction
{
    public function __construct(private readonly GroupRepository $groups)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $raw = $params['company_id'] ?? $params['customer_id'] ?? null;
        $companyId = $raw !== null && $raw !== '' ? (int) $raw : null;

        $rows = array_map(
            fn (Group $g): array => $g->toArray() + ['memberCount' => $this->groups->memberCount($g->id)],
            $this->groups->list($companyId),
        );

        return $this->json($response, 200, ['groups' => $rows]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
