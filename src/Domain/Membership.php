<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * One company membership of a login: the company (tenant) the account can access
 * plus the permissions it holds within that company. A login carries a list of
 * these; the portal shows one active company at a time.
 */
final class Membership
{
    /** @param list<string> $permissions */
    public function __construct(
        public readonly int $customerId,
        public readonly array $permissions,
    ) {
    }

    /** @return array{customerId:int, permissions:list<string>} */
    public function toArray(): array
    {
        return [
            'customerId' => $this->customerId,
            'permissions' => $this->permissions,
        ];
    }
}
