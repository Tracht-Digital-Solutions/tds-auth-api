<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\PasswordGenerator;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /admin/users/{id}/reset-password
 *
 * Generates a new temporary password, stores its hash, revokes all the user's
 * sessions (forcing re-login), and returns the temp password once.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class ResetPasswordAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly SessionRepository $sessions,
        private readonly PasswordGenerator $passwords,
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

        $password = $this->passwords->generate();
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $this->users->updatePassword($id, $hash);
        // The temp password is admin-issued — force the user to set their own.
        $this->users->update($id, ['must_change_password' => true]);
        $this->sessions->revokeAllForUser($id);

        return $this->json($response, 200, ['tempPassword' => $password]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
