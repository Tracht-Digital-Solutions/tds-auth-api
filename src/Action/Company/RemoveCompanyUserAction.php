<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /company/{companyId}/users/{id}
 *
 * Removes a user FROM THIS COMPANY.
 *
 * **It never deletes the `app_user` row**, and that is the important part: a
 * login can belong to several companies, so deleting the account because
 * company A no longer wants them would take away their access to company B —
 * silently, from a route that named only company A. If this leaves the account
 * with no memberships at all it stays: the person can still sign in and simply
 * sees nothing until a platform admin cleans up. An orphaned login is a tidiness
 * problem; a deleted one is data loss.
 *
 * Gated by JwtAuthMiddleware + CompanyAdminMiddleware.
 */
final class RemoveCompanyUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly GroupRepository $groups,
        private readonly SessionRepository $sessions,
    ) {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $companyId = (int) $request->getAttribute(CompanyAdminMiddleware::ATTR_COMPANY_ID, 0);
        $targetId = (int) ($args['id'] ?? 0);

        $target = $targetId > 0 ? $this->users->findById($targetId) : null;
        if (($deny = CompanyUserGuard::targetInCompany($target, $companyId)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }
        /** @var \Tds\AuthApi\Domain\AppUser $target */
        if (($deny = CompanyUserGuard::notPlatformAdmin($target)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $deny = CompanyUserGuard::notLastCompanyAdmin(
            $target,
            $companyId,
            $this->users->companyAdminCount($companyId),
            stillAdminAfterwards: false,
        );
        if ($deny !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        // Group assignments in this scope go with the membership; another
        // company's assignments for the same user are untouched.
        $this->groups->setForUserInCompany($targetId, $companyId, []);
        $this->users->removeCompanyMembership($targetId, $companyId);

        // Their token still carries this company until it expires.
        $this->sessions->revokeAllForUser($targetId);

        return $this->json($response, 200, ['ok' => true]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
