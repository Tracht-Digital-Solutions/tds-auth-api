<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\PasswordGenerator;

/**
 * POST /admin/users
 *
 * Body: {email, name?, password?, isAdmin?, isSupportAgent?, isBlogAuthor?,
 * bio?, avatarUrl?, memberships?, customerId?, permissions?, status?}.
 * `isBlogAuthor` grants blog-authoring access (independent of admin);
 * `bio`/`avatarUrl` are author profile fields. `memberships` is a list of
 * {customerId, permissions}; the legacy `customerId`+`permissions` pair is
 * accepted as a single-membership fallback. If `password` is omitted a temporary
 * one is generated and returned once. `isSupportAgent` is honoured only for
 * admin accounts.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true). The PHP validation here is a
 * hand-duplicate of UserCreateSchema in tds-shared — keep them in sync.
 */
final class CreateUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasswordGenerator $passwords,
        private readonly CompanyPolicyRepository $policies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $body = $request->getParsedBody();
        if (!is_array($body)) {
            return $this->json($response, 400, ['error' => 'Invalid JSON body']);
        }

        $email = strtolower(trim((string) ($body['email'] ?? '')));
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->json($response, 422, ['error' => 'Valid email required']);
        }

        $name = isset($body['name']) && $body['name'] !== null && trim((string) $body['name']) !== ''
            ? trim((string) $body['name'])
            : null;

        $isAdmin = (bool) ($body['isAdmin'] ?? false);
        // A support agent is a subset of admins — silently ignore the flag for
        // non-admin accounts so it can never be set on a customer login.
        $isSupportAgent = $isAdmin && (bool) ($body['isSupportAgent'] ?? false);
        // Blog authoring is independent of admin (a non-admin may hold it).
        $isBlogAuthor = (bool) ($body['isBlogAuthor'] ?? false);
        $bio = isset($body['bio']) && $body['bio'] !== null && trim((string) $body['bio']) !== ''
            ? mb_substr(trim((string) $body['bio']), 0, 500)
            : null;
        $avatarUrl = isset($body['avatarUrl']) && $body['avatarUrl'] !== null && trim((string) $body['avatarUrl']) !== ''
            ? mb_substr(trim((string) $body['avatarUrl']), 0, 500)
            : null;

        // Company memberships (new `memberships` shape or legacy customerId+permissions).
        $memberships = MembershipPayload::resolve($body);

        // Same refusal as the update path: company administration is a
        // per-company grant, and storing the flag for a company that does not
        // have it would save cleanly and do nothing.
        foreach ($memberships as $m) {
            if ($m['isCompanyAdmin'] && !$this->policies->get($m['companyId'])->allowCompanyAdmins) {
                return $this->json($response, 422, [
                    'error' => 'Company administration is not enabled for this company',
                    'code' => 'delegation_disabled',
                    'companyId' => $m['companyId'],
                ]);
            }
        }

        $status = (string) ($body['status'] ?? 'active');
        if (!in_array($status, ['active', 'disabled'], true)) {
            return $this->json($response, 422, ['error' => 'status must be active or disabled']);
        }

        $providedPassword = isset($body['password']) ? (string) $body['password'] : '';
        $generated = $providedPassword === '';
        if ($generated) {
            $password = $this->passwords->generate();
        } else {
            if (strlen($providedPassword) < 12) {
                return $this->json($response, 422, ['error' => 'Password must be at least 12 characters']);
            }
            $password = $providedPassword;
        }

        if ($this->users->emailExists($email)) {
            return $this->json($response, 409, ['error' => 'Email already in use']);
        }

        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        // Create the bare login (no company yet), then set the full membership
        // set — setMemberships also syncs the legacy primary customer/permissions.
        $id = $this->users->create($email, $hash, $name, $isAdmin, null, [], $status);
        $this->users->setMemberships($id, $memberships);

        // Fields not carried by create()'s signature are applied as a follow-up
        // patch: a generated temp password is admin-issued (force a change on
        // first login; an explicitly-provided password is left as set), and the
        // support-agent designation.
        $postCreate = [];
        if ($generated) {
            $postCreate['must_change_password'] = true;
        }
        if ($isSupportAgent) {
            $postCreate['is_support_agent'] = true;
        }
        if ($isBlogAuthor) {
            $postCreate['is_blog_author'] = true;
        }
        if ($bio !== null) {
            $postCreate['bio'] = $bio;
        }
        if ($avatarUrl !== null) {
            $postCreate['avatar_url'] = $avatarUrl;
        }
        if ($postCreate !== []) {
            $this->users->update($id, $postCreate);
        }
        $user = $this->users->findById($id);

        $payload = ['user' => $user?->toPublicArray()];
        if ($generated) {
            $payload['tempPassword'] = $password;
        }

        return $this->json($response, 201, $payload);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
