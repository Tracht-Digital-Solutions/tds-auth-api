<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ChallengeStore;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\PasskeyRepository;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\PermissionResolver;
use Tds\AuthApi\Service\SessionRepository;
use Tds\AuthApi\Service\WebAuthnFactory;

/**
 * POST /passkeys/login — sign in with a passkey.
 *
 * Body: base64url `{credentialId, clientDataJSON, authenticatorData, signature,
 * remember?}`. The credential id names the account — there is no email in this
 * flow — and the signature over the cookie-held challenge is the proof.
 *
 * From here on it is the ordinary login path: same JWT, same session record,
 * same cookies, and the same optional "angemeldet bleiben". A passkey replaces
 * the password, not the session model.
 */
final class PasskeyLoginAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasskeyRepository $passkeys,
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly WebAuthnFactory $webAuthn,
        private readonly ChallengeStore $challenges,
        private readonly RateLimiter $rateLimiter,
        private readonly RememberTokenService $remember,
        private readonly RememberCookieFactory $rememberCookies,
        private readonly PermissionResolver $permissions,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        // Rate-limited like the password login: signature verification is
        // expensive, and a shared bucket keeps the two paths from being played
        // off against each other.
        if (!$this->rateLimiter->check('passkey:' . $this->clientIp($request))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many login attempts. Please try again later.']);
        }

        $challenge = $this->challenges->read(
            $request->getCookieParams()[$this->challenges->cookieName()] ?? null,
        );
        if ($challenge === null) {
            return $this->json($response, 400, ['error' => 'Challenge expired. Bitte erneut versuchen.']);
        }

        $body = (array) $request->getParsedBody();
        $credentialId = trim((string) ($body['credentialId'] ?? ''));
        $clientDataJSON = self::decode((string) ($body['clientDataJSON'] ?? ''));
        $authenticatorData = self::decode((string) ($body['authenticatorData'] ?? ''));
        $signature = self::decode((string) ($body['signature'] ?? ''));
        $rememberMe = ($body['remember'] ?? false) === true;

        if ($credentialId === '' || $clientDataJSON === '' || $authenticatorData === '' || $signature === '') {
            return $this->json($response, 400, ['error' => 'Malformed credential']);
        }

        $passkey = $this->passkeys->findByCredentialId($credentialId);
        if ($passkey === null) {
            return $this->json($response, 401, ['error' => 'Invalid credentials'])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }

        // ONE instance for the whole ceremony: `getSignatureCounter()` reads the
        // counter `processGet` just parsed, so a fresh instance would always
        // answer null and quietly reset the stored count to its old value.
        $lib = $this->webAuthn->create();
        try {
            $lib->processGet(
                clientDataJSON: $clientDataJSON,
                authenticatorData: $authenticatorData,
                signature: $signature,
                credentialPublicKey: $passkey['public_key'],
                challenge: $challenge,
                // A counter that goes BACKWARDS is WebAuthn's only clone signal.
                // Passing the stored value lets the library reject that. Many
                // modern authenticators always report 0, so 0 is normal — the
                // library only compares when both sides are non-zero.
                prevSignatureCnt: $passkey['sign_count'] > 0 ? $passkey['sign_count'] : null,
                requireUserVerification: false,
                requireUserPresent: true,
            );
        } catch (\Throwable) {
            // Deliberately opaque: a verification failure must not distinguish
            // "wrong signature" from "cloned authenticator" for the caller.
            return $this->json($response, 401, ['error' => 'Invalid credentials'])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }

        $user = $this->users->findById($passkey['user_id']);
        if ($user === null) {
            return $this->json($response, 401, ['error' => 'Invalid credentials'])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }
        if (!$user->isActive()) {
            return $this->json($response, 403, ['error' => 'Account disabled'])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }

        $this->passkeys->touch($passkey['id'], $lib->getSignatureCounter() ?? $passkey['sign_count']);

        $issued = $this->jwt->issueForUser($user, $this->permissions->forUser($user->id));
        $this->sessions->record($issued['jti'], $user->companyId, $user->isAdmin, $issued['expiresAt'], $user->id);

        $result = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
            'userId' => $user->id,
            'isAdmin' => $user->isAdmin,
            'isSupportAgent' => $user->isAdmin && $user->isSupportAgent,
            'isBlogAuthor' => $user->isBlogAuthor,
            'avatarUrl' => $user->avatarUrl,
            'companies' => $user->isAdmin ? [] : array_map(static fn ($m) => $m->toArray(), $user->memberships),
            'customerId' => $user->companyId,
            'permissions' => $user->isAdmin ? [] : $user->permissions,
            // A passkey IS the stronger factor — it does not clear a pending
            // password change, but it also never triggers one on its own.
            'mustChangePassword' => $user->mustChangePassword,
            'remembered' => $rememberMe,
        ])
            ->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()))
            ->withAddedHeader('Set-Cookie', $this->challenges->expire());

        if ($rememberMe) {
            $result = $result->withAddedHeader('Set-Cookie', $this->rememberCookies->set(
                $this->remember->issue($user->id, $request->getHeaderLine('User-Agent') ?: null),
                $this->remember->ttl(),
            ));
        }
        return $result;
    }

    private static function decode(string $value): string
    {
        if ($value === '') {
            return '';
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : '';
    }

    private function clientIp(ServerRequestInterface $request): string
    {
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if ($forwarded !== '') {
            return trim(explode(',', $forwarded)[0]);
        }
        $real = $request->getHeaderLine('X-Real-IP');
        if ($real !== '') {
            return $real;
        }
        return $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
