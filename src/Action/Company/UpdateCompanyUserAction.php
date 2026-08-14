<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PATCH /company/{companyId}/users/{id}
 *
 * A company admin edits one of their own users: name, status, permissions,
 * groups, and whether that person co-administers the company.
 *
 * Every write goes through `setCompanyMembership()` — a single-row upsert.
 * `setMemberships()` replaces a user's ENTIRE set and is unreachable from here
 * on purpose: a payload that never mentions company B must not be able to drop
 * the user out of it.
 *
 * Gated by JwtAuthMiddleware + CompanyAdminMiddleware.
 */
final class UpdateCompanyUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
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
        $targetId = (int) ($args['id'] ?? 0);
        $body = (array) $request->getParsedBody();

        if (($deny = CompanyUserGuard::fields($body)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $target = $targetId > 0 ? $this->users->findById($targetId) : null;
        if (($deny = CompanyUserGuard::targetInCompany($target, $companyId)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }
        /** @var \Tds\AuthApi\Domain\AppUser $target */
        if (($deny = CompanyUserGuard::notPlatformAdmin($target)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $membership = CompanyUserGuard::membership($target, $companyId);
        $policy = $this->policies->get($companyId);
        // The per-user ceiling still applies and is NOT editable here — it is
        // the platform admin's limit on this person.
        $ceiling = $policy->ceilingFor($membership?->permissionCeiling);

        $permissions = array_key_exists('permissions', $body)
            ? Permissions::sanitize($body['permissions'])
            : ($membership?->permissions ?? []);

        $groupIds = array_key_exists('groupIds', $body)
            ? self::ids($body['groupIds'])
            : ($membership?->groupIds ?? []);

        // Withheld from this person even where a group grants it. No ceiling
        // check: a deny only ever reduces.
        $denies = array_key_exists('permissionDenies', $body)
            ? Permissions::sanitize($body['permissionDenies'])
            : ($membership?->permissionDenies ?? []);

        $groupSets = [];
        foreach ($groupIds as $groupId) {
            $group = $this->groups->find($groupId);
            if ($group === null || !$group->assignableIn($companyId)) {
                return $this->json($response, 422, [
                    'error' => 'Unknown group',
                    'code' => 'unknown_group',
                    'groupId' => $groupId,
                ]);
            }
            $groupSets[] = $group->permissions;
        }

        if (($deny = CompanyUserGuard::withinCeiling($permissions, $groupSets, $ceiling)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $isCompanyAdmin = array_key_exists('isCompanyAdmin', $body)
            ? (bool) $body['isCompanyAdmin']
            : ($membership?->isCompanyAdmin ?? false);

        $deny = CompanyUserGuard::notLastCompanyAdmin(
            $target,
            $companyId,
            $this->users->companyAdminCount($companyId),
            $isCompanyAdmin,
        );
        if ($deny !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        // Account-level fields the company admin may touch.
        $fields = [];
        if (array_key_exists('name', $body)) {
            $fields['name'] = self::trimmed($body['name'], 200);
        }
        if (array_key_exists('displayName', $body)) {
            $fields['display_name'] = self::trimmed($body['displayName'], 100);
        }
        if (array_key_exists('status', $body)) {
            $status = (string) $body['status'];
            if (!in_array($status, ['active', 'disabled'], true)) {
                return $this->json($response, 422, ['error' => 'status must be active or disabled']);
            }
            $fields['status'] = $status;
        }
        if (array_key_exists('email', $body)) {
            $email = strtolower(trim((string) $body['email']));
            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                return $this->json($response, 422, ['error' => 'Valid email required']);
            }
            if ($this->users->emailExists($email, $targetId)) {
                return $this->json($response, 409, ['error' => 'Email already in use']);
            }
            $fields['email'] = $email;
        }

        if ($fields !== []) {
            $this->users->update($targetId, $fields);
        }

        $this->users->setCompanyMembership(
            $targetId,
            $companyId,
            $permissions,
            $isCompanyAdmin,
            permissionDenies: $denies,
        );
        $this->groups->setForUserInCompany($targetId, $companyId, $groupIds);

        // Everything reachable here is authorization-relevant (permissions,
        // groups, the admin flag, the account status), so the user's sessions
        // go — the established way a change reaches a signed token.
        $this->sessions->revokeAllForUser($targetId);

        return $this->json($response, 200, [
            'user' => $this->users->findById($targetId)?->toPublicArray(),
        ]);
    }

    private static function trimmed(mixed $value, int $max): ?string
    {
        $text = trim((string) ($value ?? ''));

        return $text === '' ? null : mb_substr($text, 0, $max);
    }

    /** @return list<int> */
    private static function ids(mixed $raw): array
    {
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $value) {
            $id = (int) $value;
            if ($id > 0 && !in_array($id, $out, true)) {
                $out[] = $id;
            }
        }

        return $out;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
