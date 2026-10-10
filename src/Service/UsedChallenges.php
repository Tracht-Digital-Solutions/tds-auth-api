<?php

declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Server-side memory of the WebAuthn challenges already answered.
 *
 * The challenge lives in a signed cookie (ChallengeStore), and "single use"
 * used to rest on the response clearing that cookie. A captured cookie plus
 * its signed assertion could therefore be replayed until the cookie expired —
 * five minutes — for authenticators that do not bump a signature counter.
 */
interface UsedChallenges
{
    /** True for the FIRST claim of a challenge; false when it was already used. */
    public function claim(string $challenge, int $expiresAt): bool;
}
