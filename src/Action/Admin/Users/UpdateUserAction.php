<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PATCH /admin/users/{id}
 *
 * Partial update: {email?, name?, isAdmin?, isSupportAgent?, customerId?,
 * permissions?, status?}. `isSupportAgent` sticks only on admin accounts (and is
 * cleared when an admin is demoted). When isAdmin / isSupportAgent / permissions
 * / status / customerId change, the user's active sessions are revoked so the
 * change takes effect on their next login (fresh claims).
 *
 * Guards against the acting admin locking themselves out. Gated by
 * JwtAuthMiddleware(requireAdmin: true).
 */
final class UpdateUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly SessionRepository $sessions,
    ) {
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

        if (array_key_exists('customerId', $body)) {
            if ($body['customerId'] === null || $body['customerId'] === '') {
                $fields['customer_id'] = null;
            } else {
                $cid = (int) $body['customerId'];
                if ($cid <= 0) {
                    return $this->json($response, 422, ['error' => 'customerId must be a positive integer']);
                }
                $fields['customer_id'] = $cid;
            }
        }

        if (array_key_exists('permissions', $body)) {
            $fields['permissions'] = Permissions::sanitize($body['permissions']);
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

        if ($fields === []) {
            return $this->json($response, 200, ['user' => $user->toPublicArray()]);
        }

        $this->users->update($id, $fields);

        // Force a fresh login when authorization-relevant fields change.
        if (array_key_exists('is_admin', $fields)
            || array_key_exists('is_support_agent', $fields)
            || array_key_exists('permissions', $fields)
            || array_key_exists('status', $fields)
            || array_key_exists('customer_id', $fields)) {
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
