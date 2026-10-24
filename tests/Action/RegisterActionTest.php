<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\ConfirmRegistrationAction;
use Tds\AuthApi\Action\RegisterAction;
use Tds\AuthApi\Tests\Support\FakeAccountConfirmMailer;
use Tds\AuthApi\Tests\Support\FakeAccountConfirmRepository;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakeRateLimiter;

/**
 * POST /register + /register/confirm.
 *
 * Beyond "it works": the request never reveals whether an address has an
 * account, a pending account grants nothing, and an attacker who registers
 * someone else's address first cannot plant the password the owner activates.
 */
final class RegisterActionTest extends TestCase
{
    private FakeAppUserRepository $users;
    private FakeAccountConfirmRepository $confirms;
    private FakeAccountConfirmMailer $mailer;
    private FakeRateLimiter $rateLimiter;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
        $this->confirms = new FakeAccountConfirmRepository();
        $this->mailer = new FakeAccountConfirmMailer();
        $this->rateLimiter = new FakeRateLimiter();
    }

    public function test_a_new_address_becomes_a_pending_account_without_rights_and_gets_a_mail(): void
    {
        $response = $this->register(['name' => 'Erika', 'email' => ' Erika@Example.com', 'password' => 'correct-horse-1', 'lang' => 'en']);

        self::assertSame(202, $response->getStatusCode());
        $user = $this->users->findByEmail('erika@example.com');
        self::assertNotNull($user);
        self::assertSame('pending', $user->status);
        self::assertFalse($user->isAdmin);
        self::assertNull($user->companyId);
        self::assertFalse(password_verify('correct-horse-1', $user->passwordHash), 'a pending account must not accept the chosen password');

        self::assertCount(1, $this->mailer->sent);
        $mail = $this->mailer->sent[0];
        self::assertSame('erika@example.com', $mail['email']);
        self::assertSame(24, $mail['validHours']);
        self::assertStringStartsWith('https://auth.example/registrieren?token=', $mail['link']);
        self::assertStringEndsWith('&lang=en', $mail['link']);
        $token = $this->mailer->token();
        self::assertArrayNotHasKey($token, $this->confirms->tokens);
        self::assertArrayHasKey(hash('sha256', $token), $this->confirms->tokens);
    }

    public function test_confirming_activates_the_account_with_the_chosen_password(): void
    {
        $this->register(['name' => 'Erika', 'email' => 'erika@example.com', 'password' => 'correct-horse-1']);

        $response = $this->confirm($this->mailer->token());

        self::assertSame(204, $response->getStatusCode());
        $user = $this->users->findByEmail('erika@example.com');
        self::assertNotNull($user);
        self::assertSame('active', $user->status);
        self::assertTrue(password_verify('correct-horse-1', $user->passwordHash));
        self::assertSame(400, $this->confirm($this->mailer->token())->getStatusCode(), 'a link works once');
    }

    public function test_an_attacker_registering_first_cannot_plant_the_password(): void
    {
        // The attacker registers the victim's address with their own password…
        $this->register(['name' => 'Mallory', 'email' => 'victim@example.com', 'password' => 'attacker-pass-1']);
        // …the victim registers too and clicks THEIR link (the attacker never sees either mail).
        $this->register(['name' => 'Victim', 'email' => 'victim@example.com', 'password' => 'victim-pass-123']);

        self::assertCount(1, $this->users->list(), 'one account per address');
        $this->confirm($this->mailer->token(1));

        $user = $this->users->findByEmail('victim@example.com');
        self::assertNotNull($user);
        self::assertTrue(password_verify('victim-pass-123', $user->passwordHash));
        self::assertFalse(password_verify('attacker-pass-1', $user->passwordHash));
        self::assertSame('Victim', $user->name);
        // The attacker's token died with the confirmation.
        self::assertSame(400, $this->confirm($this->mailer->token(0))->getStatusCode());
    }

    public function test_an_existing_account_answers_the_same_and_is_never_touched(): void
    {
        $id = $this->users->create('user@example.com', password_hash('old-password-123', PASSWORD_ARGON2ID), 'User', false, 7, ['invoices:read'], 'active');
        $disabled = $this->users->create('off@example.com', password_hash('old-password-123', PASSWORD_ARGON2ID), 'Off', false, null, [], 'disabled');

        $known = $this->register(['name' => 'X', 'email' => 'user@example.com', 'password' => 'new-password-12']);
        $off = $this->register(['name' => 'X', 'email' => 'off@example.com', 'password' => 'new-password-12']);
        $fresh = $this->register(['name' => 'X', 'email' => 'fresh@example.com', 'password' => 'new-password-12']);

        self::assertSame(202, $known->getStatusCode());
        self::assertSame((string) $fresh->getBody(), (string) $known->getBody());
        self::assertSame((string) $fresh->getBody(), (string) $off->getBody());
        self::assertCount(1, $this->mailer->sent, 'only the new address gets a mail');
        self::assertTrue(password_verify('old-password-123', (string) $this->users->findById($id)?->passwordHash));
        self::assertSame('disabled', $this->users->findById($disabled)?->status);
    }

    public function test_a_stale_link_never_revives_a_disabled_account(): void
    {
        $this->register(['name' => 'Erika', 'email' => 'erika@example.com', 'password' => 'correct-horse-1']);
        $user = $this->users->findByEmail('erika@example.com');
        self::assertNotNull($user);
        $this->users->update($user->id, ['status' => 'disabled']);

        self::assertSame(400, $this->confirm($this->mailer->token())->getStatusCode());
        self::assertSame('disabled', $this->users->findById($user->id)?->status);
    }

    public function test_input_is_validated(): void
    {
        self::assertSame(400, $this->register(['name' => 'X', 'email' => 'nope', 'password' => 'long-enough-12'])->getStatusCode());
        self::assertSame(400, $this->register(['name' => ' ', 'email' => 'a@example.com', 'password' => 'long-enough-12'])->getStatusCode());
        self::assertSame(422, $this->register(['name' => 'X', 'email' => 'a@example.com', 'password' => 'short'])->getStatusCode());
        self::assertSame(400, $this->confirm('')->getStatusCode());
        self::assertSame(400, $this->confirm('unknown')->getStatusCode());
        self::assertSame([], $this->mailer->sent);
    }

    public function test_rate_limited_per_address_and_per_mailbox(): void
    {
        $this->register(['name' => 'X', 'email' => 'a@example.com', 'password' => 'long-enough-12']);

        self::assertContains('register:10.0.0.1', $this->rateLimiter->seen);
        self::assertContains('register-account:' . hash('sha256', 'a@example.com'), $this->rateLimiter->seen);

        $this->rateLimiter->allowed = false;
        self::assertSame(429, $this->register(['name' => 'X', 'email' => 'a@example.com', 'password' => 'long-enough-12'])->getStatusCode());
    }

    public function test_switched_off_answers_404(): void
    {
        $response = $this->register(['name' => 'X', 'email' => 'a@example.com', 'password' => 'long-enough-12'], enabled: false);

        self::assertSame(404, $response->getStatusCode());
        self::assertNull($this->users->findByEmail('a@example.com'));
    }

    /** @param array<string,mixed> $body */
    private function register(array $body, bool $enabled = true): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/register', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withParsedBody($body);
        $action = new RegisterAction($this->users, $this->confirms, $this->mailer, $this->rateLimiter, 'https://auth.example/registrieren', 86400, $enabled);
        return $action($request, new Response());
    }

    private function confirm(string $token): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/register/confirm', ['REMOTE_ADDR' => '10.0.0.1'])
            ->withParsedBody(['token' => $token]);
        return (new ConfirmRegistrationAction($this->users, $this->confirms, $this->rateLimiter))($request, new Response());
    }
}
