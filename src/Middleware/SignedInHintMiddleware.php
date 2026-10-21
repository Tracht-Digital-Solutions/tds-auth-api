<?php
declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Keeps a script-readable "someone is signed in on this browser" hint beside
 * the HttpOnly session — `tds_signed_in=1` on the same cookie domain.
 *
 * ### Why it exists (2026-10-06)
 *
 * The public sites (journal, tools, shop) cannot see `tds_session` — it is
 * HttpOnly, as it must be — so their account menu probed `GET /me` on every
 * page view of every anonymous visitor. That probe answers 401, the browser
 * logs the 401 to the console, and Lighthouse docks every page for it. With
 * this hint the public sites only probe when there is something to find.
 *
 * The hint carries no identity and grants nothing: it is the literal `1`, and
 * a forged one costs the forger one 401. It is derived from the response, in
 * ONE place, so no action can set or clear a session without the hint
 * following — login, passkey login, refresh, password change and logout all
 * just write their cookies as before:
 *
 * - a session or remember-me cookie set with `Max-Age > 0` → the hint is set
 *   for the longest of those lifetimes;
 * - the session cookie expired and no credential set in the same response →
 *   the hint is expired;
 * - a 200 from `GET /me` on a browser that has no hint yet (a session from
 *   before this existed) → the hint is set for one hour, so existing sessions
 *   get it on their next visit to a panel.
 */
final class SignedInHintMiddleware implements MiddlewareInterface
{
    public const NAME = 'tds_signed_in';

    /**
     * @param list<string> $credentialCookies names whose presence means "signed in"
     */
    public function __construct(
        private readonly array $credentialCookies,
        private readonly string $sessionCookie,
        private readonly string $domain,
        private readonly bool $secure,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        $longest = 0;
        $sessionExpired = false;
        foreach ($response->getHeader('Set-Cookie') as $line) {
            $name = strtok($line, '=');
            if (!in_array($name, $this->credentialCookies, true)) {
                continue;
            }
            $maxAge = preg_match('/;\s*Max-Age=(-?\d+)/i', $line, $m) === 1 ? (int) $m[1] : null;
            $value = substr($line, strlen((string) $name) + 1, (int) strpos($line . ';', ';') - strlen((string) $name) - 1);
            if ($maxAge !== null && $maxAge > 0 && $value !== '') {
                $longest = max($longest, $maxAge);
            } elseif ($name === $this->sessionCookie) {
                $sessionExpired = true;
            }
        }

        if ($longest > 0) {
            return $response->withAddedHeader('Set-Cookie', $this->cookie('1', $longest));
        }
        if ($sessionExpired) {
            return $response->withAddedHeader('Set-Cookie', $this->cookie('', 0));
        }

        $cookies = $request->getCookieParams();
        if (
            $request->getMethod() === 'GET'
            && preg_match('#/me$#', $request->getUri()->getPath()) === 1
            && $response->getStatusCode() === 200
            && !isset($cookies[self::NAME])
        ) {
            return $response->withAddedHeader('Set-Cookie', $this->cookie('1', 3600));
        }

        return $response;
    }

    private function cookie(string $value, int $maxAge): string
    {
        $parts = [
            self::NAME . '=' . $value,
            'Path=/',
            'Max-Age=' . $maxAge,
            'Domain=' . $this->domain,
            'SameSite=Lax',
        ];
        if ($this->secure) {
            $parts[] = 'Secure';
        }
        // Deliberately NOT HttpOnly: the public sites' scripts must read it.
        return implode('; ', $parts);
    }
}
