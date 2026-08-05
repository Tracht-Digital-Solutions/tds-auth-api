<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * The "angemeldet bleiben" cookie, as a distinct type.
 *
 * It carries the same attributes as the session cookie — httpOnly, `SameSite=Lax`,
 * `Domain=.tracht-digital.de` so one remembered login covers every sibling
 * frontend — and differs only in name and lifetime. A separate class rather
 * than a second `CookieFactory` binding purely so the container can inject the
 * two by type without a named alias, and so no call site can reach for the
 * wrong one.
 */
final class RememberCookieFactory
{
    public function __construct(private readonly CookieFactory $inner)
    {
    }

    public function set(string $value, int $maxAgeSeconds): string
    {
        return $this->inner->set($value, $maxAgeSeconds);
    }

    public function expire(): string
    {
        return $this->inner->expire();
    }

    public function name(): string
    {
        return $this->inner->name();
    }
}
