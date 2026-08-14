<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PATCH /admin/users/{id}
 *
 * Partial update: {email?, name?, isAdmin?, isSupportAgent?, isBlogAuthor?,
 * bio?, avatarUrl?, memberships?, customerId?, permissions?, status?}.
 * Passing `memberships` (or the legacy
 * `customerId`+`permissions` fallback) replaces the account's full company
 * membership set. `isSupportAgent` sticks only on admin accounts (and is cleared
 * when an admin is demoted). When isAdmin / isSupportAgent / memberships / status
 * change, the user's active sessions are revoked so the change takes effect on
 * their next login (fresh claims).
 *
 * Guards against the acting admin locking themselves out. Gated by
 * JwtAuthMiddleware(requireAdmin: true).
 */
final class UpdateUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly SessionRepository $sessions,
        private readonly CompanyPolicyRepository $policies,
    ) {
    }

    /**
     * The first membership that asks for a company admin the company may not
     * have, as an error payload — or null when every one of them is fine.
     *
     * @param list<array{companyId:int, isCompanyAdmin:bool}> $memberships
     * @return array<string,mixed>|null
     */
    private function delegationDenied(array $memberships): ?array
    {
        foreach ($memberships as $m) {
            if (!$m['isCompanyAdmin']) {
                continue;
            }
            if (!$this->policies->get($m['companyId'])->allowCompanyAdmins) {
                return [
                    'error' => 'Company administration is not enabled for this company',
                    'code' => 'delegation_disabled',
                    'companyId' => $m['companyId'],
                ];
            }
        }

        return null;
    }

    /** @param array<string,string> $args */
    public function __invoke(ServerRequestInterface $request, Response $response, array $args): ResponseInterface
    {
        $id = (int) ($args['id'] ?? 0);
        $user = $id > 0 ? $this->users->findById($id) : null;
        if ($user === null) {
            return $this->json($response, 404, ['error' => 'User not found']);
        }

        $body = $request->getParsedBody();
        if (!is_array($body)) {
            return $this->json($response, 400, ['error' => 'Invalid JSON body']);
        }

        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $actingUid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        $fields = [];

        if (array_key_exists('email', $body)) {
            $email = strtolower(trim((string) $body['email']));
            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                return $this->json($response, 422, ['error' => 'Valid email required']);
            }
            if ($this->users->emailExists($email, $id)) {
                return $this->json($response, 409, ['error' => 'Email already in use']);
            }
            $fields['email'] = $email;
        }

        if (array_key_exists('name', $body)) {
            $name = $body['name'] !== null && trim((string) $body['name']) !== ''
                ? trim((string) $body['name'])
                : null;
            $fields['name'] = $name;
        }

        if (array_key_exists('isAdmin', $body)) {
            $fields['is_admin'] = (bool) $body['isAdmin'];
        }

        if (array_key_exists('isSupportAgent', $body)) {
            // A support agent is a subset of admins. Coerce the flag against the
            // account's resulting admin state (the incoming isAdmin if present,
            // otherwise the stored one) so it can never stick on a non-admin.
            $resultingAdmin = array_key_exists('is_admin', $fields)
                ? (bool) $fields['is_admin']
                : $user->isAdmin;
            $fields['is_support_agent'] = $resultingAdmin && (bool) $body['isSupportAgent'];
        } elseif (array_key_exists('is_admin', $fields) && $fields['is_admin'] === false) {
            // Demoting an admin to non-admin also clears any agent designation.
            $fields['is_support_agent'] = false;
        }

        if (array_key_exists('isBlogAuthor', $body)) {
            $fields['is_blog_author'] = (bool) $body['isBlogAuthor'];
        }
        if (array_key_exists('bio', $body)) {
            $fields['bio'] = $body['bio'] !== null && trim((string) $body['bio']) !== ''
                ? mb_substr(trim((string) $body['bio']), 0, 500)
                : null;
        }
        if (array_key_exists('avatarUrl', $body)) {
            $fields['avatar_url'] = $body['avatarUrl'] !== null && trim((string) $body['avatarUrl']) !== ''
                ? mb_substr(trim((string) $body['avatarUrl']), 0, 500)
                : null;
        }

        // Company memberships are handled below via setMemberships (which also
        // syncs the legacy customer_id/permissions columns), not as plain fields.
        $membershipsPresent = MembershipPayload::present($body);
        $memberships = $membershipsPresent ? MembershipPayload::resolve($body) : [];

        // Company administration is a per-company grant. Storing the flag for a
        // company that has not been switched on would save cleanly and do
        // nothing — the resolver folds it away and the middleware refuses the
        // route — so it is refused here instead, naming the fix. This service
        // does not do stored-but-inert.
        if (($deny = $this->delegationDenied($memberships)) !== null) {
            return $this->json($response, 422, $deny);
        }

        if (array_key_exists('status', $body)) {
            $status = (string) $body['status'];
            if (!in_array($status, ['active', 'disabled'], true)) {
                return $this->json($response, 422, ['error' => 'status must be active or disabled']);
            }
            $fields['status'] = $status;
        }

        // Self-lockout guard: don't let the acting admin remove their own
        // admin access or disable their own account.
        if ($id === $actingUid) {
            if ((array_key_exists('is_admin', $fields) && $fields['is_admin'] === false)
                || (array_key_exists('status', $fields) && $fields['status'] === 'disabled')) {
                return $this->json($response, 409, ['error' => 'Cannot remove your own admin access']);
            }
        }

        if ($fields === [] && !$membershipsPresent) {
            return $this->json($response, 200, ['user' => $user->toPublicArray()]);
        }

        if ($fields !== []) {
            $this->users->update($id, $fields);
        }
        if ($membershipsPresent) {
            $this->users->setMemberships($id, $memberships);
        }

        // Force a fresh login when authorization-relevant fields change (the
        // blog_author claim included, so blog access takes effect immediately).
        if ($membershipsPresent
            || array_key_exists('is_admin', $fields)
            || array_key_exists('is_support_agent', $fields)
            || array_key_exists('is_blog_author', $fields)
            || array_key_exists('status', $fields)) {
            $this->sessions->revokeAllForUser($id);
        }

        $updated = $this->users->findById($id);
        return $this->json($response, 200, ['user' => $updated?->toPublicArray()]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
