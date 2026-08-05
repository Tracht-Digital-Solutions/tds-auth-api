<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * GET /admin/users  (optional ?customer_id=N to filter to one company)
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class ListUsersAction
{
    public function __construct(private readonly AppUserRepository $users)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $customerId = isset($params['customer_id']) && $params['customer_id'] !== ''
            ? (int) $params['customer_id']
            : null;

        $rows = array_map(
            static fn ($u) => $u->toPublicArray(),
            $this->users->list($customerId),
        );

        $response->getBody()->write(json_encode(['users' => $rows]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
