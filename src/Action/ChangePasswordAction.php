<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PUT /password   (alias: PUT /customer/password)
 *
 * Body: {"old": "...", "new": "..."}.
 *
 * Works for any authenticated user (admin or customer). Verifies the old
 * password, rehashes the new one, revokes the current jti and issues a fresh
 * JWT so other devices on the old token fail their next refresh.
 *
 * Gated by JwtAuthMiddleware (any valid session).
 */
final class ChangePasswordAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;
        $jti = (string) ($claims['jti'] ?? '');

        $body = $request->getParsedBody();
        $old = is_array($body) ? (string) ($body['old'] ?? '') : '';
        $new = is_array($body) ? (string) ($body['new'] ?? '') : '';

        if ($old === '' || $new === '') {
            return $this->json($response, 400, ['error' => 'Old and new password required']);
        }
        if (strlen($new) < 12) {
            return $this->json($response, 422, ['error' => 'New password must be at least 12 characters']);
        }
        if (hash_equals($old, $new)) {
            return $this->json($response, 422, ['error' => 'New password must differ from old']);
        }

        $user = $uid > 0 ? $this->users->findById($uid) : null;
        if ($user === null) {
            // Token said user N exists but the row is gone. Treat as logout.
            if ($jti !== '') {
                $this->sessions->revoke($jti);
            }
            return $this->json($response, 401, ['error' => 'User not found'])
                ->withHeader('Set-Cookie', $this->cookies->expire());
        }

        if (!password_verify($old, $user->passwordHash)) {
            return $this->json($response, 401, ['error' => 'Old password incorrect']);
        }

        $hash = password_hash($new, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $this->users->updatePassword($user->id, $hash);
        // A self-chosen password clears any forced-change flag (the bootstrap
        // admin or an admin-issued temp password is now replaced).
        if ($user->mustChangePassword) {
            $this->users->update($user->id, ['must_change_password' => false]);
        }

        // Revoke the current jti, then issue a fresh session so the caller
        // stays logged in. Other devices on the old jti fail their next refresh.
        if ($jti !== '') {
            $this->sessions->revoke($jti);
        }
        $issued = $this->jwt->issueForUser($user);
        $this->sessions->record($issued['jti'], $user->customerId, $user->isAdmin, $issued['expiresAt'], $user->id);

        return $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
        ])->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
