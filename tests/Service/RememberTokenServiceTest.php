<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Tests\Support\FakeRememberTokenRepository;

/**
 * "30 Tage angemeldet bleiben" is a 30-day credential. These assertions are the
 * properties that keep that from being a 30-day liability:
 *
 *  - the validator is never stored in a form a database dump could use,
 *  - the pair rotates on every use, so a copied cookie works at most once, and
 *  - a wrong validator against a real selector destroys the row rather than
 *    leaving a guessing window open.
 */
final class RememberTokenServiceTest extends TestCase
{
    private FakeRememberTokenRepository $repo;
    private RememberTokenService $service;

    protected function setUp(): void
    {
        $this->repo = new FakeRememberTokenRepository();
        $this->service = new RememberTokenService($this->repo, 2592000);
    }

    public function test_issued_cookie_is_selector_and_validator(): void
    {
        $cookie = $this->service->issue(7, 'UA/1.0');

        self::assertMatchesRegularExpression('/^[0-9a-f]{32}:[0-9a-f]{32}$/', $cookie);
        self::assertCount(1, $this->repo->rows);
    }

    public function test_validator_is_never_stored_in_plaintext(): void
    {
        // The single property that makes a stolen database dump useless.
        $cookie = $this->service->issue(7);
        [$selector, $validator] = explode(':', $cookie);

        $stored = $this->repo->rows[$selector]['validator_hash'];
        self::assertNotSame($validator, $stored);
        self::assertSame(hash('sha256', $validator), $stored);
    }

    public function test_consume_returns_the_user_and_rotates_the_pair(): void
    {
        $first = $this->service->issue(42);
        $result = $this->service->consume($first);

        self::assertNotNull($result);
        self::assertSame(42, $result['userId']);
        self::assertNotSame($first, $result['cookie'], 'the pair must rotate');
        // Exactly one live row: the old selector is gone, the new one is not.
        self::assertCount(1, $this->repo->rows);
        self::assertArrayNotHasKey(explode(':', $first)[0], $this->repo->rows);
    }

    public function test_a_consumed_cookie_cannot_be_replayed(): void
    {
        // What turns cookie theft into one unexpected logout instead of 30 days
        // of silent access.
        $cookie = $this->service->issue(42);
        self::assertNotNull($this->service->consume($cookie));
        self::assertNull($this->service->consume($cookie));
    }

    public function test_wrong_validator_destroys_the_row(): void
    {
        $cookie = $this->service->issue(42);
        $selector = explode(':', $cookie)[0];

        self::assertNull($this->service->consume($selector . ':' . str_repeat('0', 32)));
        // A real selector with a wrong validator means the cookie was copied or
        // is being guessed — leaving the row would keep the guessing window open.
        self::assertArrayNotHasKey($selector, $this->repo->rows);
    }

    public function test_expired_token_is_rejected_and_dropped(): void
    {
        $past = new RememberTokenService($this->repo, -10);
        $cookie = $past->issue(42);

        self::assertNull($past->consume($cookie));
        self::assertSame([], $this->repo->rows);
    }

    public function test_malformed_cookies_are_rejected_without_touching_storage(): void
    {
        foreach (['', 'no-colon', ':', 'abc:', ':abc'] as $bad) {
            self::assertNull($this->service->consume($bad), $bad);
        }
        self::assertSame([], $this->repo->deleted);
    }

    public function test_unknown_selector_is_rejected(): void
    {
        self::assertNull($this->service->consume(str_repeat('a', 32) . ':' . str_repeat('b', 32)));
    }

    public function test_forget_all_drops_every_token_of_that_user_only(): void
    {
        $this->service->issue(1);
        $this->service->issue(1);
        $keep = $this->service->issue(2);

        $this->service->forgetAllForUser(1);

        self::assertCount(1, $this->repo->rows);
        self::assertNotNull($this->service->consume($keep));
    }

    public function test_forget_drops_only_the_presented_device(): void
    {
        $mine = $this->service->issue(1);
        $other = $this->service->issue(1);

        $this->service->forget($mine);

        self::assertNull($this->service->consume($mine));
        self::assertNotNull($this->service->consume($other));
    }

    public function test_user_agent_is_truncated_not_rejected(): void
    {
        // Provenance only — never used for authentication, so an absurd header
        // must not be able to fail a login.
        $this->service->issue(1, str_repeat('x', 5000));
        $row = reset($this->repo->rows);
        self::assertSame(200, mb_strlen((string) $row['user_agent']));
    }
}
