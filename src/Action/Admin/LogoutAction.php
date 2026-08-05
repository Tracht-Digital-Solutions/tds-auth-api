<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /admin/login
 *
 * Revokes the current session (if a valid cookie/Bearer is present)
 * and clears the cookie. Returns 204 either way — logout is
 * idempotent.
 */
final class LogoutAction
{
    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly RememberTokenService $remember,
        private readonly RememberCookieFactory $rememberCookies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $token = $this->extractToken($request);
        if ($token !== null) {
            try {
                $claims = $this->jwt->verify($token);
                if (isset($claims['jti']) && is_string($claims['jti'])) {
                    $this->sessions->revoke($claims['jti']);
                }
            } catch (\Throwable) {
                // ignore — already invalid, nothing to revoke
            }
        }

        // Logging out must also end "angemeldet bleiben". Without this the next
        // request would silently refresh a brand-new session from the remember
        // cookie and the user would appear never to have logged out.
        $rememberCookie = $request->getCookieParams()[$this->rememberCookies->name()] ?? null;
        if (is_string($rememberCookie) && $rememberCookie !== '') {
            $this->remember->forget($rememberCookie);
        }

        return $response
            ->withStatus(204)
            ->withHeader('Set-Cookie', $this->cookies->expire())
            ->withAddedHeader('Set-Cookie', $this->rememberCookies->expire());
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
}
