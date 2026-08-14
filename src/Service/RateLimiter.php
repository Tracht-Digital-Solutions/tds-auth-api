<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

interface RateLimiter
{
    /** @return array{allowed: bool, remaining: int} */
    public function check(string $bucket): array;
}
