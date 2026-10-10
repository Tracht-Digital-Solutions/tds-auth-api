<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\SessionRepository;

/**
 * GET /admin/sessions
 *
 * Returns currently-active sessions (not revoked, not expired) so
 * the admin panel can list who's signed in and surface revoke
 * controls. Newest first.
 *
 * Gated by AdminAuthMiddleware — shared ADMIN_TOKEN Bearer.
 *
 * Optional `?limit=N` (1-500, default 200).
 */
final class ListSessionsAction
{
    public function __construct(private readonly SessionRepository $sessions)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $limitRaw = isset($params['limit']) ? (int) $params['limit'] : 200;
        $limit = max(1, min(500, $limitRaw));

        $rows = $this->sessions->listActive($limit);

        $response->getBody()->write(json_encode(['sessions' => $rows]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
