<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Company;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\GroupRepository;

/**
 * POST /company/{companyId}/users
 *
 * A company admin adds a user to their own company. Two shapes:
 *
 * - the email belongs to nobody → a new account is created with a temporary
 *   password, returned **once**;
 * - the email already has an account → it gains a membership of this company.
 *   Deliberately: one login, many companies, is the whole point of the model —
 *   refusing here would push people into a second account for the same person.
 *
 * Gated by JwtAuthMiddleware + CompanyAdminMiddleware.
 */
final class CreateCompanyUserAction
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
        $body = (array) $request->getParsedBody();

        if (($deny = CompanyUserGuard::fields($body)) !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $email = strtolower(trim((string) ($body['email'] ?? '')));
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->json($response, 422, ['error' => 'Valid email required']);
        }

        $policy = $this->policies->get($companyId);
        $permissions = Permissions::sanitize($body['permissions'] ?? []);
        $groupIds = self::ids($body['groupIds'] ?? []);
        // Rights withheld from this one person even where a group grants them.
        // Needs no ceiling check — a deny only ever reduces.
        $denies = Permissions::sanitize($body['permissionDenies'] ?? []);

        $groupSets = [];
        foreach ($groupIds as $groupId) {
            $group = $this->groups->find($groupId);
            // A group from another company is not merely forbidden, it is
            // meaningless here — reject rather than silently ignore, or the
            // admin sees a saved user with a group that was never applied.
            if ($group === null || !$group->assignableIn($companyId)) {
                return $this->json($response, 422, [
                    'error' => 'Unknown group',
                    'code' => 'unknown_group',
                    'groupId' => $groupId,
                ]);
            }
            $groupSets[] = $group->permissions;
        }

        $deny = CompanyUserGuard::withinCeiling(
            $permissions,
            $groupSets,
            $policy->ceilingFor(null),
        );
        if ($deny !== null) {
            return $this->json($response, $deny[0], $deny[1]);
        }

        $existing = $this->users->findByEmail($email);
        if ($existing !== null && $existing->isAdmin) {
            // Adding a platform admin to a company through this route would
            // create a membership nobody here may then edit.
            return $this->json($response, 403, ['error' => 'Platform administrators cannot be managed here']);
        }
        if ($existing !== null && CompanyUserGuard::membership($existing, $companyId) !== null) {
            return $this->json($response, 409, ['error' => 'User is already a member of this company']);
        }

        $temporaryPassword = null;
        $userId = $existing?->id;

        // The seat check and the write share one transaction + row lock: a
        // plain count-then-insert lets two concurrent requests both see the
        // last free seat, which is how a cap quietly stops being one.
        $granted = $this->policies->withSeat($companyId, function () use (
            &$userId,
            &$temporaryPassword,
            $email,
            $body,
            $companyId,
            $permissions,
            $groupIds,
            $existing,
        ): void {
            if ($existing === null) {
                $temporaryPassword = bin2hex(random_bytes(9));
                $hash = password_hash($temporaryPassword, PASSWORD_ARGON2ID);
                $userId = $this->users->create(
                    $email,
                    (string) $hash,
                    self::trimmed($body['name'] ?? null, 200),
                    false,
                    null,
                    [],
                    'active',
                );
                $this->users->update($userId, ['must_change_password' => true]);
            }

            $this->users->setCompanyMembership(
                (int) $userId,
                $companyId,
                $permissions,
                (bool) ($body['isCompanyAdmin'] ?? false),
                permissionDenies: $denies,
            );
            $this->groups->setForUserInCompany((int) $userId, $companyId, $groupIds);
        });

        if (!$granted) {
            $policy = $this->policies->get($companyId);
            return $this->json($response, 409, [
                'error' => 'No seats left for this company',
                'code' => 'seat_limit',
                'max' => $policy->maxUsers,
                'used' => $this->policies->seatsUsed($companyId),
            ]);
        }

        $user = $this->users->findById((int) $userId);

        return $this->json($response, 201, [
            'user' => $user?->toPublicArray(),
            // Shown once, in-flow (never a toast — it has to be read and
            // copied). Null when the account already existed: the company
            // admin has no business resetting a password that also unlocks
            // another company.
            'temporaryPassword' => $temporaryPassword,
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
