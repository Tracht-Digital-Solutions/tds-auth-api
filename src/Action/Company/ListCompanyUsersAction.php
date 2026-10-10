<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\GroupRepository;

/**
 * GET /company/{companyId}/users
 *
 * The company admin's own user list, plus everything their editor needs to
 * render without three more round-trips: the seat count, the ceiling in force,
 * and the groups they may assign.
 *
 * Scoped in SQL (`AppUserRepository::list($companyId)` joins the membership
 * table). A company admin is never handed another company's rows to filter.
 *
 * Gated by JwtAuthMiddleware + CompanyAdminMiddleware.
 */
final class ListCompanyUsersAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly GroupRepository $groups,
        private readonly CompanyPolicyRepository $policies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $companyId = (int) $request->getAttribute(CompanyAdminMiddleware::ATTR_COMPANY_ID, 0);

        $policy = $this->policies->get($companyId);
        $used = $this->policies->seatsUsed($companyId);

        // Platform admins are filtered out: they are not manageable here (see
        // CompanyUserGuard), so listing them would only offer actions that
        // always 403.
        $members = array_values(array_filter(
            $this->users->list($companyId),
            static fn (AppUser $u): bool => !$u->isAdmin,
        ));

        $rows = array_map(static function (AppUser $user) use ($companyId): array {
            $membership = CompanyUserGuard::membership($user, $companyId);

            return [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                'displayName' => $user->displayName,
                'label' => $user->label(),
                'status' => $user->status,
                'permissions' => $membership?->permissions ?? [],
                'groupIds' => $membership?->groupIds ?? [],
                'isCompanyAdmin' => $membership?->isCompanyAdmin ?? false,
                // The RAW stored decision, not the effective set: the editor
                // has to show which rights are withheld, and an effective list
                // cannot express "the group grants it and we took it away".
                'permissionDenies' => $membership?->permissionDenies ?? [],
            ];
        }, $members);

        return $this->json($response, 200, [
            'users' => $rows,
            'seats' => [
                'used' => $used,
                'max' => $policy->maxUsers,
                // Null max ⇒ null remaining, rather than a made-up large
                // number the UI would have to special-case anyway.
                'remaining' => $policy->maxUsers === null ? null : max(0, $policy->maxUsers - $used),
            ],
            // What this admin may grant. Null = no ceiling.
            'allowedPermissions' => $policy->allowedPermissions,
            'allowCustomGroups' => $policy->allowCustomGroups,
            // Always true by the time anyone reads this — the middleware
            // refuses the route otherwise — but the client renders the
            // Firmenadmin control from it, so it is stated rather than assumed.
            'allowCompanyAdmins' => $policy->allowCompanyAdmins,
            'groups' => array_map(
                static fn ($g): array => $g->toArray(),
                self::assignable($this->groups->list($companyId), $policy->allowedPermissions),
            ),
        ]);
    }

    /**
     * Only groups whose permissions fit inside the ceiling.
     *
     * Offering one that does not would let a company admin escalate by
     * assignment — and the write would refuse it anyway, so showing it is just
     * a trap.
     *
     * @param list<\Tds\AuthApi\Domain\Group> $groups
     * @param list<string>|null $ceiling
     * @return list<\Tds\AuthApi\Domain\Group>
     */
    private static function assignable(array $groups, ?array $ceiling): array
    {
        if ($ceiling === null) {
            return $groups;
        }

        return array_values(array_filter(
            $groups,
            static fn ($g): bool => \Tds\AuthApi\Domain\CompanyPolicy::rejected($g->permissions, $ceiling) === [],
        ));
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
