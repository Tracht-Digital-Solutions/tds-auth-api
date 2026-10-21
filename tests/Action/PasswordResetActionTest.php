<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\ConfirmPasswordResetAction;
use Tds\AuthApi\Action\RequestPasswordResetAction;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakePasswordResetMailer;
use Tds\AuthApi\Tests\Support\FakePasswordResetRepository;
use Tds\AuthApi\Tests\Support\FakeRateLimiter;
use Tds\AuthApi\Tests\Support\FakeRememberTokenRepository;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

/**
 * POST /password-reset + /password-reset/confirm (tds-auth-api#5).
 *
 * The two properties that matter beyond "it works": the request never tells
 * a caller whether an address has an account, and a reset ends every session
 * and remember token of the user — otherwise the device the user stopped
 * trusting keeps its access for 30 days.
 */
final class PasswordResetActionTest extends TestCase
{
    private FakeAppUserRepository $users;
    private FakePasswordResetRepository $resets;
    private FakePasswordResetMailer $mailer;
    private FakeRateLimiter $rateLimiter;
    private FakeSessionRepository $sessions;
    private FakeRememberTokenRepository $rememberRepo;
    private RememberTokenService $remember;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
        $this->resets = new FakePasswordResetRepository();
        $this->mailer = new FakePasswordResetMailer();
        $this->rateLimiter = new FakeRateLimiter();
        $this->sessions = new FakeSessionRepository();
        $this->rememberRepo = new FakeRememberTokenRepository();
        $this->remember = new RememberTokenService($this->rememberRepo, 2592000);
    }

    private function seed(string $status = 'active'): int
    {
        return $this->users->create(
            'user@example.com',
            password_hash('old-password-123', PASSWORD_ARGON2ID),
            'User',
            false,
            7,
            ['invoices:read'],
            $status,
        );
    }

    public function test_known_address_gets_a_mail_with_a_one_time_link(): void
    {
        $this->seed();

        $response = $this->request(['email' => 'User@Example.com ', 'lang' => 'en']);

        self::assertSame(202, $response->getStatusCode());
        self::assertCount(1, $this->mailer->sent);
        $mail = $this->mailer->sent[0];
        self::assertSame('user@example.com', $mail['email']);
        self::assertSame('en', $mail['lang']);
        self::assertSame(60, $mail['validMinutes']);
        self::assertStringStartsWith('https://auth.example/passwort-vergessen?token=', $mail['link']);
        self::assertStringEndsWith('&lang=en', $mail['link']);
        // Only the hash is stored, never the token from the link.
        $token = $this->mailer->lastToken();
        self::assertSame(64, strlen($token));
        self::assertArrayNotHasKey($token, $this->resets->tokens);
        self::assertArrayHasKey(hash('sha256', $token), $this->resets->tokens);
    }

    public function test_unknown_and_disabled_addresses_answer_the_same_and_send_nothing(): void
    {
        $this->seed('disabled');

        $unknown = $this->request(['email' => 'nobody@example.com']);
        $disabled = $this->request(['email' => 'user@example.com']);

        self::assertSame(202, $unknown->getStatusCode());
        self::assertSame(202, $disabled->getStatusCode());
        self::assertSame((string) $unknown->getBody(), (string) $disabled->getBody());
        self::assertSame([], $this->mailer->sent);
        self::assertSame([], $this->resets->tokens);
    }

    public function test_a_failed_mail_call_still_answers_202(): void
    {
        $this->seed();
        $this->mailer->delivers = false;

        self::assertSame(202, $this->request(['email' => 'user@example.com'])->getStatusCode());
    }

    public function test_invalid_address_is_400(): void
    {
        self::assertSame(400, $this->request(['email' => 'not-an-address'])->getStatusCode());
    }

    public function test_request_is_rate_limited_per_address_and_per_mailbox(): void
    {
        $this->seed();
        $this->request(['email' => 'user@example.com']);

        self::assertContains('reset:10.0.0.1', $this->rateLimiter->seen);
        self::assertContains('reset-account:' . hash('sha256', 'user@example.com'), $this->rateLimiter->seen);

        $this->rateLimiter->allowed = false;
        self::assertSame(429, $this->request(['email' => 'user@example.com'])->getStatusCode());
    }

    public function test_only_the_newest_link_works(): void
    {
        $this->seed();
        $this->request(['email' => 'user@example.com']);
        $first = $this->mailer->lastToken();
        $this->request(['email' => 'user@example.com']);

        self::assertSame(400, $this->confirm(['token' => $first, 'new' => 'brand-new-password'])->getStatusCode());
        self::assertSame(204, $this->confirm(['token' => $this->mailer->lastToken(), 'new' => 'brand-new-password'])->getStatusCode());
    }

    public function test_confirm_sets_the_password_and_ends_every_session_and_remember_token(): void
    {
        $id = $this->seed();
        $this->users->update($id, ['must_change_password' => true]);
        $this->sessions->record('laptop', 7, false, time() + 900, $id);
        $this->remember->issue($id, 'old phone');
        $this->request(['email' => 'user@example.com']);

        $response = $this->confirm(['token' => $this->mailer->lastToken(), 'new' => 'brand-new-password']);

        self::assertSame(204, $response->getStatusCode());
        $user = $this->users->findById($id);
        self::assertNotNull($user);
        self::assertTrue(password_verify('brand-new-password', $user->passwordHash));
        self::assertFalse($user->mustChangePassword);
        self::assertTrue($this->sessions->isRevoked('laptop'));
        self::assertContains($id, $this->sessions->revokedUsers);
        self::assertSame([], $this->rememberRepo->rows);
        self::assertSame([], $this->resets->tokens);
    }

    public function test_a_link_works_once(): void
    {
        $this->seed();
        $this->request(['email' => 'user@example.com']);
        $token = $this->mailer->lastToken();

        self::assertSame(204, $this->confirm(['token' => $token, 'new' => 'brand-new-password'])->getStatusCode());
        self::assertSame(400, $this->confirm(['token' => $token, 'new' => 'another-password-1'])->getStatusCode());
    }

    public function test_an_expired_link_is_rejected(): void
    {
        $this->seed();
        $this->request(['email' => 'user@example.com']);
        $token = $this->mailer->lastToken();
        $this->resets->expire(hash('sha256', $token));

        self::assertSame(400, $this->confirm(['token' => $token, 'new' => 'brand-new-password'])->getStatusCode());
    }

    public function test_a_short_password_does_not_burn_the_link(): void
    {
        $this->seed();
        $this->request(['email' => 'user@example.com']);
        $token = $this->mailer->lastToken();

        self::assertSame(422, $this->confirm(['token' => $token, 'new' => 'short'])->getStatusCode());
        self::assertSame(204, $this->confirm(['token' => $token, 'new' => 'brand-new-password'])->getStatusCode());
    }

    public function test_an_account_disabled_after_the_mail_cannot_reset(): void
    {
        $id = $this->seed();
        $this->request(['email' => 'user@example.com']);
        $this->users->update($id, ['status' => 'disabled']);

        self::assertSame(400, $this->confirm(['token' => $this->mailer->lastToken(), 'new' => 'brand-new-password'])->getStatusCode());
    }

    /** @param array<string,mixed> $body */
    private function request(array $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/password-reset', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withParsedBody($body);
        $action = new RequestPasswordResetAction(
            $this->users,
            $this->resets,
            $this->mailer,
            $this->rateLimiter,
            'https://auth.example/passwort-vergessen',
            3600,
        );
        return $action($request, new Response());
    }

    /** @param array<string,mixed> $body */
    private function confirm(array $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/password-reset/confirm', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withParsedBody($body);
        $action = new ConfirmPasswordResetAction($this->users, $this->resets, $this->sessions, $this->remember, $this->rateLimiter);
        return $action($request, new Response());
    }
}
