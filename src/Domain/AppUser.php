<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * A login identity. Spans both panels: `isAdmin` grants admin-panel access; a
 * non-null `customerId` ties the account to a company (tenant), scoped by
 * `permissions`. Multiple users may share one `customerId`.
 *
 * `passwordHash` is loaded for verification but never serialized — use
 * {@see self::toPublicArray()} for API output.
 */
final class AppUser
{
    /** @param list<string> $permissions */
    public function __construct(
        public readonly int $id,
        public readonly string $email,
        public readonly ?string $name,
        public readonly bool $isAdmin,
        public readonly ?int $customerId,
        public readonly array $permissions,
        public readonly string $status,
        public readonly string $passwordHash,
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /** @return array<string,mixed> */
    public function toPublicArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            'isAdmin' => $this->isAdmin,
            'customerId' => $this->customerId,
            'permissions' => $this->permissions,
            'status' => $this->status,
        ];
    }
}
