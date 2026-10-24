<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * The WebAuthn challenge, carried in a signed cookie instead of server state.
 *
 * Every WebAuthn ceremony is two round trips: the server issues a random
 * challenge, the authenticator signs over it, and the server must recognise
 * *that* challenge on the way back. The usual home for it is a PHP session —
 * which this API deliberately does not have (it is stateless, and the gateway
 * may run it in-process behind any of several hosts).
 *
 * So the challenge travels in a short-lived httpOnly cookie, HMAC-signed so the
 * browser cannot choose its own. That is safe because the challenge is not a
 * secret: its only job is to be unpredictable and single-ceremony. What must not
 * happen is a client picking a challenge it has a pre-recorded signature for —
 * which the signature prevents.
 *
 * `SameSite=Lax` + `Domain=.tracht-digital.de` matches the session cookie, so
 * the ceremony works from any first-party frontend.
 */
final class ChallengeStore
{
    /** Ceremonies are interactive; five minutes is generous. */
    private const TTL_SECONDS = 300;

    public function __construct(
        private readonly string $secret,
        private readonly string $cookieName,
        private readonly string $domain,
        private readonly bool $secure,
    ) {
    }

    public function cookieName(): string
    {
        return $this->cookieName;
    }

    /** Set-Cookie value carrying `$challenge` (raw bytes). */
    public function issue(string $challenge): string
    {
        $payload = self::b64($challenge) . '.' . (time() + self::TTL_SECONDS);
        $value = $payload . '.' . hash_hmac('sha256', $payload, $this->secret);

        $parts = [
            sprintf('%s=%s', $this->cookieName, rawurlencode($value)),
            'Path=/',
            sprintf('Max-Age=%d', self::TTL_SECONDS),
            sprintf('Domain=%s', $this->domain),
            'HttpOnly',
            'SameSite=Lax',
        ];
        if ($this->secure) {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }

    /** Set-Cookie value that clears it — a challenge is single-use. */
    public function expire(): string
    {
        $parts = [
            sprintf('%s=', $this->cookieName),
            'Path=/',
            'Max-Age=0',
            sprintf('Domain=%s', $this->domain),
            'HttpOnly',
            'SameSite=Lax',
        ];
        if ($this->secure) {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }

    /**
     * Recover the raw challenge from a presented cookie, or null when it is
     * missing, malformed, forged or expired.
     */
    public function read(?string $cookieValue): ?string
    {
        if (!is_string($cookieValue) || $cookieValue === '') {
            return null;
        }
        $parts = explode('.', $cookieValue);
        if (count($parts) !== 3) {
            return null;
        }
        [$encoded, $expiry, $signature] = $parts;

        $expected = hash_hmac('sha256', $encoded . '.' . $expiry, $this->secret);
        if (!hash_equals($expected, $signature)) {
            return null;
        }
        if ((int) $expiry < time()) {
            return null;
        }

        $raw = self::unb64($encoded);
        return $raw === '' ? null : $raw;
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function unb64(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : '';
    }
}
