<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Companies;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;

/**
 * GET /admin/companies/{companyId}/policy
 *
 * What a company may do on its own: how many users it may have, which
 * permissions its admin may hand out, and whether it may define its own groups.
 * A company with no stored policy reads back as unlimited — which is the state
 * every company starts in, and why the feature is opt-in rather than a
 * migration everybody has to survive.
 *
 * `seatsUsed` rides along so the editor can show "7 von 10" without a second
 * call, and can refuse to set a cap below what is already in use.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true) — the PLATFORM admin's
 * surface. A company admin never reaches this: the ceiling is the limit
 * imposed ON them.
 */
final class CompanyPolicyAction
{
    public function __construct(
        private readonly CompanyPolicyRepository $policies,
        private readonly AppUserRepository $users,
    ) {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $companyId = (int) ($args['companyId'] ?? 0);
        if ($companyId <= 0) {
            return $this->json($response, 404, ['error' => 'Company not found']);
        }

        $policy = $this->policies->get($companyId);

        return $this->json($response, 200, [
            'policy' => $policy->toArray(),
            'seatsUsed' => $this->policies->seatsUsed($companyId),
            'companyAdmins' => $this->users->companyAdminCount($companyId),
        ]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
