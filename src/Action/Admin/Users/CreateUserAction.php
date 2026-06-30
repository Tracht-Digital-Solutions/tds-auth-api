<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\PasswordGenerator;

/**
 * POST /admin/users
 *
 * Body: {email, name?, password?, isAdmin?, customerId?, permissions?, status?}.
 * If `password` is omitted a temporary one is generated and returned once.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true). The PHP validation here is a
 * hand-duplicate of UserCreateSchema in tds-shared — keep them in sync.
 */
final class CreateUserAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasswordGenerator $passwords,
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

        $customerId = null;
        if (isset($body['customerId']) && $body['customerId'] !== null && $body['customerId'] !== '') {
            $customerId = (int) $body['customerId'];
            if ($customerId <= 0) {
                return $this->json($response, 422, ['error' => 'customerId must be a positive integer']);
            }
        }

        $status = (string) ($body['status'] ?? 'active');
        if (!in_array($status, ['active', 'disabled'], true)) {
            return $this->json($response, 422, ['error' => 'status must be active or disabled']);
        }

        $permissions = Permissions::sanitize($body['permissions'] ?? []);

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

        $id = $this->users->create($email, $hash, $name, $isAdmin, $customerId, $permissions, $status);
        // A generated temp password is admin-issued — force a change on first
        // login. An explicitly-provided password is left as the admin set it.
        if ($generated) {
            $this->users->update($id, ['must_change_password' => true]);
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
