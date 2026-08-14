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
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\PermissionResolver;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PUT /password   (alias: PUT /customer/password)
 *
 * Body: {"old": "...", "new": "..."}.
 *
 * Works for any authenticated user (admin or customer). Verifies the old
 * password, rehashes the new one, revokes ALL of the user's existing sessions
 * and issues a fresh JWT for the current device — so any other session (a lost
 * or stolen device) is terminated rather than left able to refresh for the
 * 30-day refresh TTL.
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
        private readonly RememberTokenService $remember,
        private readonly RememberCookieFactory $rememberCookies,
        private readonly PermissionResolver $permissions,
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

        // A password change invalidates *every* existing session for this user
        // (OWASP: changing the password must terminate all other sessions — the
        // whole point when you're locking out a device you no longer trust), then
        // we issue + record a fresh one so the caller stays logged in here. Only
        // revoking the current jti (as before) left other sessions able to keep
        // refreshing for the 30-day refresh TTL. Matches ResetPasswordAction /
        // UpdateUserAction, which also revokeAllForUser.
        $this->sessions->revokeAllForUser($user->id);
        // …and every "angemeldet bleiben" token with them. Revoking sessions
        // alone would be theatre: the untrusted device still holds a 30-day
        // remember cookie and would mint itself a brand-new session on its very
        // next request. The current device is signed out of the long-lived
        // option too and simply opts in again at the next login.
        $this->remember->forgetAllForUser($user->id);
        $issued = $this->jwt->issueForUser($user, $this->permissions->forUser($user->id));
        $this->sessions->record($issued['jti'], $user->companyId, $user->isAdmin, $issued['expiresAt'], $user->id);

        return $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
        ])
            ->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()))
            ->withAddedHeader('Set-Cookie', $this->rememberCookies->expire());
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
