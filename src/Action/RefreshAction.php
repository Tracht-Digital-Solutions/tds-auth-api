<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\PermissionResolver;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /refresh
 *
 * Two ways in, in this order:
 *
 *  1. **A still-valid JWT.** Its signature and session row are checked and the
 *     claims are carried forward without a DB lookup.
 *  2. **The "angemeldet bleiben" cookie**, when there is no usable JWT — an
 *     expired token, or none at all. The remember token is verified and
 *     ROTATED, the user is re-read from the database, and a completely fresh
 *     JWT is issued from their *current* flags and memberships.
 *
 * That second path is what makes the 30-day option safe: the session JWT stays
 * short-lived (downstream services verify it against the JWKS and never consult
 * this database, so a long JWT would be a long non-revocable credential), and
 * staying signed in becomes a re-authentication rather than a longer token. A
 * disabled account stops working at the next refresh, not in 30 days.
 */
final class RefreshAction
{
    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly AppUserRepository $users,
        private readonly RememberTokenService $remember,
        private readonly RememberCookieFactory $rememberCookies,
        private readonly PermissionResolver $permissions,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $token = $this->extractToken($request);
        $claims = null;
        if ($token !== null) {
            try {
                $claims = $this->jwt->verify($token);
            } catch (\Throwable) {
                $claims = null;
            }
        }

        if ($claims === null) {
            // `$token !== null` distinguishes "you sent a JWT I cannot use" from
            // "you sent nothing" — the two need different fixes on the caller's
            // side, and the remember path must not blur them.
            return $this->refreshFromRememberCookie($request, $response, presentedToken: $token !== null);
        }

        $jti = (string) ($claims['jti'] ?? '');
        if ($jti === '' || $this->sessions->isRevoked($jti)) {
            // A revoked session must not be resurrected by a remember cookie
            // that was issued before the revocation.
            return $this->json($response, 401, ['error' => 'Session revoked']);
        }

        $admin = (bool) ($claims['admin'] ?? false);
        $supportAgent = (bool) ($claims['support_agent'] ?? false);
        $blogAuthor = (bool) ($claims['blog_author'] ?? false);
        $companyId = self::companyIdFrom($claims);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : null;
        $permissions = isset($claims['permissions']) && is_array($claims['permissions'])
            ? array_values(array_map('strval', $claims['permissions']))
            : [];
        $companies = isset($claims['companies']) && is_array($claims['companies'])
            ? $this->normaliseCompanies($claims['companies'])
            : [];

        // A non-admin with no company is legitimate and used to throw here.
        // `LoginAction` never checked, so such an account signed in fine and
        // then hit a 500 on its first hourly refresh — the panel's backstop
        // sees the 500 while `/me` still answers 200, so the session neither
        // recovers nor ends and the user degrades in place. Company
        // membership is optional by design (a user may belong to none, one or
        // several), so issue with `company_id: null` and no companies.
        $email = isset($claims['email']) && is_string($claims['email']) ? $claims['email'] : null;
        $name = isset($claims['name']) && is_string($claims['name']) ? $claims['name'] : null;

        // Carry the principal forward without a DB lookup. Authorization
        // changes take effect via session revocation (see UpdateUserAction),
        // which forces a fresh login rather than relying on refresh.
        $issued = $this->jwt->issuePrincipal($admin, $companyId, $uid, $permissions, $supportAgent, $companies, $blogAuthor, $email, $name);

        $this->sessions->record($issued['jti'], $companyId, $admin, $issued['expiresAt'], $uid);

        $response = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
        ]);
        return $response->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    /**
     * The company from either claim spelling.
     *
     * A token minted before the `customer` → `company` rename carries
     * `customer_id`, and it stays valid for up to an hour after the deploy —
     * reading only the new name would drop the company on the first refresh
     * and silently strip a portal user of their tenant. Removed with the rest
     * of the aliases in the follow-up release.
     *
     * @param array<string,mixed> $claims
     */
    private static function companyIdFrom(array $claims): ?int
    {
        foreach (['company_id', 'customer_id'] as $key) {
            if (isset($claims[$key]) && is_int($claims[$key])) {
                return $claims[$key];
            }
        }

        return null;
    }

    /**
     * The "angemeldet bleiben" path. Verifies + rotates the remember cookie and
     * mints a fresh JWT from the user's CURRENT record — deliberately a full
     * re-read rather than replaying stale claims, because 30 days is long
     * enough for permissions, memberships or the account status to have changed.
     */
    private function refreshFromRememberCookie(
        ServerRequestInterface $request,
        Response $response,
        bool $presentedToken = false,
    ): ResponseInterface {
        $cookie = $request->getCookieParams()[$this->rememberCookies->name()] ?? null;
        if (!is_string($cookie) || $cookie === '') {
            return $this->json($response, 401, [
                'error' => $presentedToken ? 'Invalid token' : 'No token presented',
            ]);
        }

        $rotated = $this->remember->consume($cookie, $request->getHeaderLine('User-Agent') ?: null);
        if ($rotated === null) {
            // Unknown, expired or mismatched — all indistinguishable to the
            // caller. Clear the cookie so the browser stops presenting it.
            return $this->json($response, 401, ['error' => 'Invalid token'])
                ->withHeader('Set-Cookie', $this->rememberCookies->expire());
        }

        $user = $this->users->findById($rotated['userId']);
        // Three ways a remembered login stops being valid, all checked HERE
        // rather than by revoking tokens at the other end: the account is gone,
        // it was disabled, or an admin reset the password (which sets
        // must-change-password). Re-reading the user on every refresh is what
        // lets this stay a single check instead of four scattered revocations.
        if ($user === null || !$user->isActive() || $user->mustChangePassword) {
            // Drop every token this user has, not just the one presented.
            $this->remember->forgetAllForUser($rotated['userId']);
            return $this->json($response, 401, ['error' => 'Session revoked'])
                ->withHeader('Set-Cookie', $this->rememberCookies->expire());
        }

        $issued = $this->jwt->issueForUser($user, $this->permissions->forUser($user->id));
        $this->sessions->record($issued['jti'], $user->companyId, $user->isAdmin, $issued['expiresAt'], $user->id);

        return $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
            'remembered' => true,
        ])
            ->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()))
            ->withAddedHeader('Set-Cookie', $this->rememberCookies->set($rotated['cookie'], $this->remember->ttl()));
    }

    /**
     * Coerce the decoded `companies` claim (each entry may be an array or a
     * stdClass after JWT decode) into the shape issuePrincipal expects.
     *
     * @param array<int,mixed> $raw
     * @return list<array{id:int, permissions:list<string>, admin:bool}>
     */
    private function normaliseCompanies(array $raw): array
    {
        $out = [];
        foreach ($raw as $entry) {
            $e = (array) $entry;
            $id = isset($e['id']) ? (int) $e['id'] : 0;
            if ($id <= 0) {
                continue;
            }
            $perms = isset($e['permissions']) && is_array($e['permissions'])
                ? array_values(array_map('strval', $e['permissions']))
                : [];
            $out[] = [
                'id' => $id,
                'permissions' => $perms,
                // Carry the company-admin flag forward. Dropping it here would
                // quietly demote a company admin at their first hourly refresh
                // — they would keep working right up until the token rotated,
                // then start getting 403s from /company/* with nothing having
                // changed.
                'admin' => (bool) ($e['admin'] ?? false),
            ];
        }
        return $out;
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && preg_match('/^Bearer\s+(.+)$/i', $auth, $m) === 1) {
            return $m[1];
        }
        $cookie = $request->getCookieParams()[$this->cookies->name()] ?? null;
        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
