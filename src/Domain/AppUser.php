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
    /**
     * @param list<string> $permissions primary (default) company's permissions
     * @param list<Membership> $memberships all company memberships
     */
    public function __construct(
        public readonly int $id,
        public readonly string $email,
        public readonly ?string $name,
        public readonly bool $isAdmin,
        /** @deprecated primary membership's company — read `$memberships`. */
        public readonly ?int $customerId,
        /** @deprecated primary membership's permissions — read `$memberships`. */
        public readonly array $permissions,
        public readonly string $status,
        public readonly string $passwordHash,
        /** When true the user must set a new password before using either panel. */
        public readonly bool $mustChangePassword = false,
        /**
         * Marks an admin as a support agent — tickets can be assigned to this
         * user (the "Bearbeiter"). Only meaningful when `$isAdmin` is true.
         */
        public readonly bool $isSupportAgent = false,
        public readonly array $memberships = [],
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
            'isSupportAgent' => $this->isSupportAgent,
            'memberships' => array_map(static fn (Membership $m): array => $m->toArray(), $this->memberships),
            'customerId' => $this->customerId,
            'permissions' => $this->permissions,
            'status' => $this->status,
            'mustChangePassword' => $this->mustChangePassword,
        ];
    }
}
