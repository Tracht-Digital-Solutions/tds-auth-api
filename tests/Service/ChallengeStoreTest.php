<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\ChallengeStore;

/**
 * The WebAuthn challenge travels in a signed cookie because this API keeps no
 * session. The signature is the whole security argument: a challenge the client
 * can choose is a challenge it can have a pre-recorded signature for, which
 * makes the ceremony replayable.
 */
final class ChallengeStoreTest extends TestCase
{
    private ChallengeStore $store;

    protected function setUp(): void
    {
        $this->store = new ChallengeStore('secret', 'tds_wa_challenge', '.local', secure: false);
    }

    /** Extract the raw cookie value out of a Set-Cookie header. */
    private function value(string $setCookie): string
    {
        $first = explode(';', $setCookie)[0];
        return rawurldecode(explode('=', $first, 2)[1]);
    }

    public function test_round_trips_the_raw_challenge(): void
    {
        $challenge = random_bytes(32);
        $cookie = $this->value($this->store->issue($challenge));

        self::assertSame($challenge, $this->store->read($cookie));
    }

    public function test_rejects_a_tampered_challenge(): void
    {
        // The attack this exists to stop: swapping in a challenge the caller
        // already holds a signature for.
        $cookie = $this->value($this->store->issue(random_bytes(32)));
        [, $expiry, $signature] = explode('.', $cookie);
        $forged = rtrim(strtr(base64_encode('chosen-by-me'), '+/', '-_'), '=');

        self::assertNull($this->store->read($forged . '.' . $expiry . '.' . $signature));
    }

    public function test_rejects_a_cookie_signed_with_another_secret(): void
    {
        $other = new ChallengeStore('different', 'tds_wa_challenge', '.local', secure: false);
        $cookie = $this->value($other->issue(random_bytes(32)));

        self::assertNull($this->store->read($cookie));
    }

    public function test_rejects_an_extended_expiry(): void
    {
        // Moving the expiry out is covered by the same HMAC — it is signed
        // together with the challenge, not beside it.
        $cookie = $this->value($this->store->issue(random_bytes(32)));
        [$encoded, , $signature] = explode('.', $cookie);

        self::assertNull($this->store->read($encoded . '.' . (time() + 999999) . '.' . $signature));
    }

    public function test_rejects_an_expired_cookie(): void
    {
        $encoded = rtrim(strtr(base64_encode('old'), '+/', '-_'), '=');
        $expiry = time() - 1;
        $payload = $encoded . '.' . $expiry;
        $valid = $payload . '.' . hash_hmac('sha256', $payload, 'secret');

        self::assertNull($this->store->read($valid), 'signature is valid but the window has closed');
    }

    public function test_rejects_malformed_and_missing_cookies(): void
    {
        foreach ([null, '', 'a', 'a.b', 'a.b.c.d'] as $bad) {
            self::assertNull($this->store->read($bad), var_export($bad, true));
        }
    }

    public function test_expire_clears_the_cookie(): void
    {
        // A challenge is single-use; leaving it set would allow a second
        // ceremony against the same value.
        self::assertStringContainsString('Max-Age=0', $this->store->expire());
        self::assertStringContainsString('Domain=.local', $this->store->expire());
    }

    public function test_marks_the_cookie_httponly_and_lax(): void
    {
        $header = $this->store->issue(random_bytes(32));
        self::assertStringContainsString('HttpOnly', $header);
        self::assertStringContainsString('SameSite=Lax', $header);
        self::assertStringNotContainsString('Secure', $header, 'not in a non-production build');
    }

    public function test_marks_the_cookie_secure_in_production(): void
    {
        $secure = new ChallengeStore('secret', 'c', '.local', secure: true);
        self::assertStringContainsString('Secure', $secure->issue(random_bytes(32)));
    }
}
