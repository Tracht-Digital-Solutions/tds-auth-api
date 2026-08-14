<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Builds Set-Cookie header values for the session JWT. We use a
 * shared cross-subdomain cookie (Domain=.tracht-digital.de) so the
 * admin and customer panels can authenticate against the same auth
 * API without redirecting users.
 */
final class CookieFactory
{
    public function __construct(
        private readonly string $name,
        private readonly string $domain,
        private readonly bool $secure,
    ) {
    }

    public function set(string $token, int $maxAgeSeconds): string
    {
        $parts = [
            sprintf('%s=%s', $this->name, rawurlencode($token)),
            'Path=/',
            sprintf('Max-Age=%d', $maxAgeSeconds),
            sprintf('Domain=%s', $this->domain),
            'HttpOnly',
            'SameSite=Lax',
        ];
        if ($this->secure) {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }

    public function expire(): string
    {
        $parts = [
            sprintf('%s=', $this->name),
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

    public function name(): string
    {
        return $this->name;
    }
}
