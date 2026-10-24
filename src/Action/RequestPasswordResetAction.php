<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ClientIp;
use Tds\AuthApi\Service\PasswordResetMailer;
use Tds\AuthApi\Service\PasswordResetRepository;
use Tds\AuthApi\Service\RateLimiter;

/**
 * POST /password-reset
 *
 * Body: {"email": "...", "lang": "de"|"en"}.
 *
 * Answers 202 for every well-formed address — known, unknown or disabled — so
 * the route cannot be used to find out who has an account. Only an active
 * account gets a token and a mail. The token is 32 random bytes, sent once in
 * the link and stored only as its SHA-256.
 *
 * Rate-limited per client address and per mailbox, like the login: the address
 * bucket alone would let a botnet flood one inbox.
 */
final class RequestPasswordResetAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasswordResetRepository $resets,
        private readonly PasswordResetMailer $mailer,
        private readonly RateLimiter $rateLimiter,
        private readonly string $resetUrl,
        private readonly int $ttlSeconds = 3600,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        if (!$this->rateLimiter->check('reset:' . ClientIp::from($request))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $body = $request->getParsedBody();
        $email = is_array($body) ? strtolower(trim((string) ($body['email'] ?? ''))) : '';
        $lang = is_array($body) && ($body['lang'] ?? '') === 'en' ? 'en' : 'de';

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->json($response, 400, ['error' => 'Valid email required']);
        }
        if (!$this->rateLimiter->check('reset-account:' . hash('sha256', $email))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $user = $this->users->findByEmail($email);
        if ($user !== null && $user->isActive()) {
            $token = bin2hex(random_bytes(32));
            $this->resets->create($user->id, hash('sha256', $token), $this->ttlSeconds);
            $this->mailer->send(
                $user->email,
                $user->displayName ?? $user->name,
                $this->link($token, $lang),
                $lang,
                intdiv($this->ttlSeconds, 60),
            );
        }

        return $this->json($response, 202, ['ok' => true]);
    }

    /** The token rides in the query string; the reset page reads it and posts it back. */
    private function link(string $token, string $lang): string
    {
        $separator = str_contains($this->resetUrl, '?') ? '&' : '?';
        $query = 'token=' . $token . ($lang === 'en' ? '&lang=en' : '');
        return $this->resetUrl . $separator . $query;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
