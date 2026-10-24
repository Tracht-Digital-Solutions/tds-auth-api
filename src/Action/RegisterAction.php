<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AccountConfirmMailer;
use Tds\AuthApi\Service\AccountConfirmRepository;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ClientIp;
use Tds\AuthApi\Service\RateLimiter;

/**
 * POST /register — self-registration with a confirmed address.
 *
 * Body: {"name": "...", "email": "...", "password": "...", "lang": "de"|"en"}.
 *
 * Answers 202 for every acceptable request, whether the address is new,
 * pending or already has an account: the route must not tell a caller who
 * is registered. Only a new or still pending address gets a mail.
 *
 * A new address becomes a `pending` account with NO usable password, no
 * company, no permissions and no admin flag. The chosen password and name
 * ride on the confirmation token, not on the account: whoever registers an
 * address first must not be able to plant a password that the real owner
 * later activates by clicking their own link. Each link applies its own
 * request's password, and only the mailbox owner can click any of them.
 *
 * Rate-limited per client address and per mailbox, like the reset.
 */
final class RegisterAction
{
    public const MIN_PASSWORD_LENGTH = 12;

    public function __construct(
        private readonly AppUserRepository $users,
        private readonly AccountConfirmRepository $confirms,
        private readonly AccountConfirmMailer $mailer,
        private readonly RateLimiter $rateLimiter,
        private readonly string $confirmUrl,
        private readonly int $ttlSeconds = 86400,
        private readonly bool $enabled = true,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        if (!$this->enabled) {
            return $this->json($response, 404, ['error' => 'Not found']);
        }
        if (!$this->rateLimiter->check('register:' . ClientIp::from($request))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $body = $request->getParsedBody();
        $body = is_array($body) ? $body : [];
        $email = strtolower(trim((string) ($body['email'] ?? '')));
        $name = trim((string) ($body['name'] ?? ''));
        $password = (string) ($body['password'] ?? '');
        $lang = ($body['lang'] ?? '') === 'en' ? 'en' : 'de';

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
            return $this->json($response, 400, ['error' => 'Valid email required']);
        }
        if ($name === '' || mb_strlen($name) > 120) {
            return $this->json($response, 400, ['error' => 'Name required']);
        }
        if (strlen($password) < self::MIN_PASSWORD_LENGTH || strlen($password) > 1024) {
            return $this->json($response, 422, ['error' => 'Password must be at least 12 characters']);
        }
        if (!$this->rateLimiter->check('register-account:' . hash('sha256', $email))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $user = $this->users->findByEmail($email);
        if ($user !== null && $user->status !== 'pending') {
            // Active or disabled: nothing happens, and the answer is the same.
            return $this->json($response, 202, ['ok' => true]);
        }

        $passwordHash = password_hash($password, PASSWORD_ARGON2ID);
        if ($passwordHash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $userId = $user?->id ?? $this->users->create(
            $email,
            // Unusable until confirmed: no password verifies against a hash of
            // random bytes nobody ever saw.
            (string) password_hash(bin2hex(random_bytes(32)), PASSWORD_ARGON2ID),
            $name,
            false,
            null,
            [],
            'pending',
        );

        $token = bin2hex(random_bytes(32));
        $this->confirms->create($userId, hash('sha256', $token), $passwordHash, $name, $this->ttlSeconds);
        $this->mailer->send($email, $name, $this->link($token, $lang), $lang, max(1, intdiv($this->ttlSeconds, 3600)));

        return $this->json($response, 202, ['ok' => true]);
    }

    /** The token rides in the query string; the confirm page reads it and posts it back. */
    private function link(string $token, string $lang): string
    {
        $separator = str_contains($this->confirmUrl, '?') ? '&' : '?';
        return $this->confirmUrl . $separator . 'token=' . $token . ($lang === 'en' ? '&lang=en' : '');
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
