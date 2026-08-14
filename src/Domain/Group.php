<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * A named, persisted set of permissions.
 *
 * `companyId === 0` is a PLATFORM group, assignable in any company. Anything
 * else is owned by that company and only assignable within it.
 *
 * `isSystem` marks the four seeded groups: their permission sets stay editable
 * (that is what makes them useful), but the slug and the row are locked,
 * because other things reference them by slug.
 */
final class Group
{
    public const PLATFORM = 0;

    /** @param list<string> $permissions */
    public function __construct(
        public readonly int $id,
        public readonly int $companyId,
        public readonly string $slug,
        public readonly string $name,
        public readonly ?string $description,
        public readonly array $permissions,
        public readonly bool $isSystem = false,
    ) {
    }

    public function isPlatform(): bool
    {
        return $this->companyId === self::PLATFORM;
    }

    /** Assignable by/within $companyId? Platform groups are assignable anywhere. */
    public function assignableIn(int $companyId): bool
    {
        return $this->isPlatform() || $this->companyId === $companyId;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'companyId' => $this->companyId,
            'slug' => $this->slug,
            'name' => $this->name,
            'description' => $this->description,
            'permissions' => $this->permissions,
            'isSystem' => $this->isSystem,
            'scope' => $this->isPlatform() ? 'platform' : 'company',
        ];
    }
}
