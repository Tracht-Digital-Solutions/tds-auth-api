<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * A login identity. Spans both panels: `isAdmin` grants admin-panel access; a
 * non-null `companyId` ties the account to a company (Firma), scoped by
 * `permissions`. Multiple users may share one `companyId`.
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
        /** @deprecated denormalised primary membership — read `$memberships`. */
        public readonly ?int $companyId,
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
        /**
         * Grants blog-authoring access (see the `blog_author` JWT claim). A
         * (usually non-admin) login that may write blog posts and appears as an
         * author on the public blog. Admins are implicitly authors too.
         */
        public readonly bool $isBlogAuthor = false,
        /** Public profile-picture URL, or null. */
        public readonly ?string $avatarUrl = null,
        /** Short author bio shown on the public blog author page, or null. */
        public readonly ?string $bio = null,
        public readonly array $memberships = [],
        /**
         * The short name the user picked for themselves, shown in the panel's
         * profile menu. Null falls back to {@see self::label()}. Distinct from
         * `$name`, which is the account name an admin maintains and which also
         * drives the blog byline — self-service must not rewrite that.
         */
        public readonly ?string $displayName = null,
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * What to call this person in a UI, in descending order of what they
     * chose themselves. Never empty — an avatar or a menu with a blank name
     * reads as a broken page, and an email is always present.
     */
    public function label(): string
    {
        foreach ([$this->displayName, $this->name] as $candidate) {
            $trimmed = trim((string) $candidate);
            if ($trimmed !== '') {
                return $trimmed;
            }
        }
        return $this->email;
    }

    /** @return array<string,mixed> */
    public function toPublicArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            'displayName' => $this->displayName,
            'isAdmin' => $this->isAdmin,
            'isSupportAgent' => $this->isSupportAgent,
            'isBlogAuthor' => $this->isBlogAuthor,
            'avatarUrl' => $this->avatarUrl,
            'bio' => $this->bio,
            'memberships' => array_map(static fn (Membership $m): array => $m->toArray(), $this->memberships),
            'companyId' => $this->companyId,
            // Deprecated alias, emitted for one release so a client built
            // against the old name keeps rendering. Dropped in the follow-up.
            'customerId' => $this->companyId,
            'permissions' => $this->permissions,
            'status' => $this->status,
            'mustChangePassword' => $this->mustChangePassword,
        ];
    }
}
