<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * "Angemeldet bleiben" — issue, verify and rotate long-lived remember-me
 * tokens.
 *
 * WHY THIS IS NOT JUST A LONGER JWT. Every other service verifies the session
 * token against the JWKS and never talks to this database, so a JWT's lifetime
 * is also its non-revocability window. Handing out a 30-day JWT would mean a
 * disabled account keeps working for 30 days. Instead the JWT stays at an hour
 * and this token buys the right to mint a new one.
 *
 * The cookie value is `selector:validator`:
 *  - the **selector** is what the row is found by, so the lookup never compares
 *    a secret and cannot leak one through timing;
 *  - only a SHA-256 of the **validator** is stored, so a database dump yields no
 *    usable cookies. It is compared with `hash_equals`.
 *
 * **The pair rotates on every use.** A stolen cookie therefore works at most
 * once before the legitimate browser's next refresh invalidates it — the theft
 * surfaces as an unexpected logout instead of 30 days of silent access.
 */
final class RememberTokenService
{
    /** Hex length of each half. 16 bytes of CSPRNG each. */
    private const HALF_BYTES = 16;

    public function __construct(
        private readonly RememberTokenRepository $repository,
        /** Lifetime in seconds — the "30 Tage" of the checkbox. */
        private readonly int $ttlSeconds,
    ) {
    }

    public function ttl(): int
    {
        return $this->ttlSeconds;
    }

    /**
     * Mint a token for a user and return the cookie value.
     * The validator exists in plaintext exactly once: right here.
     */
    public function issue(int $userId, ?string $userAgent = null): string
    {
        $selector = bin2hex(random_bytes(self::HALF_BYTES));
        $validator = bin2hex(random_bytes(self::HALF_BYTES));

        $this->repository->store(
            userId: $userId,
            selector: $selector,
            validatorHash: hash('sha256', $validator),
            expiresAtUnix: time() + $this->ttlSeconds,
            userAgent: $userAgent !== null ? mb_substr($userAgent, 0, 200) : null,
        );

        return $selector . ':' . $validator;
    }

    /**
     * Verify a presented cookie and, on success, **rotate** it: the old row is
     * deleted and a fresh pair issued.
     *
     * @return array{userId:int, cookie:string}|null null for any failure —
     *         malformed, unknown, expired or mismatched. The caller must not be
     *         able to tell those apart.
     */
    public function consume(string $cookieValue, ?string $userAgent = null): ?array
    {
        $parts = explode(':', $cookieValue, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$selector, $validator] = $parts;
        if ($selector === '' || $validator === '') {
            return null;
        }

        $row = $this->repository->findBySelector($selector);
        if ($row === null) {
            return null;
        }

        // Constant-time: a byte-wise early return would let an attacker who can
        // guess a selector brute-force the validator one character at a time.
        if (!hash_equals($row['validator_hash'], hash('sha256', $validator))) {
            // A wrong validator against a REAL selector means the cookie was
            // copied or is being guessed. Drop the row: better one unexpected
            // logout than an open guessing window.
            $this->repository->deleteBySelector($selector);
            return null;
        }

        if ($row['expires_at'] <= time()) {
            $this->repository->deleteBySelector($selector);
            return null;
        }

        $this->repository->deleteBySelector($selector);
        return [
            'userId' => $row['user_id'],
            'cookie' => $this->issue($row['user_id'], $userAgent),
        ];
    }

    /** Forget one presented cookie (logout on this device). */
    public function forget(string $cookieValue): void
    {
        $selector = explode(':', $cookieValue, 2)[0] ?? '';
        if ($selector !== '') {
            $this->repository->deleteBySelector($selector);
        }
    }

    /** Forget every token of a user — password change, disable, admin revoke. */
    public function forgetAllForUser(int $userId): void
    {
        $this->repository->deleteForUser($userId);
    }
}
