<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\RateLimiter;

final class FakeRateLimiter implements RateLimiter
{
    /** @var list<string> */
    public array $seen = [];

    public function __construct(
        public bool $allowed = true,
        public int $remaining = 9,
    ) {
    }

    public function check(string $bucket): array
    {
        $this->seen[] = $bucket;
        return ['allowed' => $this->allowed, 'remaining' => $this->remaining];
    }
}
