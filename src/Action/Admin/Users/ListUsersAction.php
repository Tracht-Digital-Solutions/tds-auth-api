<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * GET /admin/users  (optional ?company_id=N to filter to one company)
 *
 * `?customer_id=` is accepted as a deprecated alias for one release.
 *
 * The filter joins the membership table (see `PdoAppUserRepository::list()`).
 * It used to compare `app_user.company_id`, the DENORMALISED primary
 * membership, so a user whose second or third company was the one being asked
 * about simply did not appear — the filter quietly under-reported exactly the
 * multi-company case the model exists to support.
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
        $raw = $params['company_id'] ?? $params['customer_id'] ?? null;
        $companyId = $raw !== null && $raw !== '' ? (int) $raw : null;

        $rows = array_map(
            static fn ($u) => $u->toPublicArray(),
            $this->users->list($companyId),
        );

        $response->getBody()->write(json_encode(['users' => $rows]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
