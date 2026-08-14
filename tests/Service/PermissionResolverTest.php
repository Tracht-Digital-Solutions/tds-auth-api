<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Membership;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\PermissionResolver;
use Tds\AuthApi\Tests\Support\FakeCompanyPolicyRepository;
use Tds\AuthApi\Tests\Support\FakeGroupRepository;
use Tds\AuthApi\Tests\Support\Keys;

/**
 * The layer between the stored rows and everything that publishes them.
 *
 * ### This file exists because the class had no consumers at all
 *
 * `PermissionResolver` was registered in the container and injected nowhere for
 * a full release: all four login paths called `issueForUser($user)` with no
 * resolver and `MeAction` returned the raw membership row. So groups could be
 * created, assigned and displayed — and granted nothing — while the ceiling was
 * enforced when writing and never when resolving. Nothing was red, because
 * nothing looked. **The token assertions below are the regression guard**: they
 * fail if the wiring is ever dropped again.
 */
final class PermissionResolverTest extends TestCase
{
    private FakeGroupRepository $groups;
    private FakeCompanyPolicyRepository $policies;
    private PermissionResolver $resolver;

    protected function setUp(): void
    {
        $this->groups = new FakeGroupRepository();
        $this->policies = new FakeCompanyPolicyRepository();
        $this->resolver = new PermissionResolver($this->groups, $this->policies);
    }

    /**
     * The first `companies` entry of a verified token, as an array.
     *
     * JWT decoding yields stdClass for nested objects — the same normalisation
     * CompanyAdminMiddleware has to do, and the reason a naive array access
     * here fails while the production code works.
     *
     * @return array<string,mixed>
     */
    private static function firstCompany(JwtService $jwt, string $token): array
    {
        $claims = $jwt->verify($token);

        return (array) json_decode((string) json_encode($claims['companies']), true)[0];
    }

    /** A real signer, so the token assertions go through verify() rather than a stub. */
    private static function jwt(): JwtService
    {
        $keys = new Keys();

        return new JwtService(
            privateKeyPem: $keys->privatePem,
            publicKeyPem: $keys->publicPem,
            keyId: 'test-kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );
    }

    public function test_a_group_assigned_in_the_company_grants_its_rights(): void
    {
        $this->groups->add(new Group(1, Group::PLATFORM, 'buchhaltung', 'Buchhaltung', null, ['invoices:read', 'invoices:pay']));
        $this->groups->assign(userId: 5, companyId: 7, groupId: 1);

        $result = $this->resolver->forMembership(5, new Membership(7, ['tickets:read']));

        self::assertSame(['tickets:read', 'invoices:read', 'invoices:pay'], $result);
    }

    public function test_a_globally_assigned_group_applies_inside_every_company(): void
    {
        // Scope 0 is the "applies everywhere" assignment; missing it would make
        // a global group silently company-specific.
        $this->groups->add(new Group(2, Group::PLATFORM, 'nur_lesen', 'Nur Lesen', null, ['tickets:read']));
        $this->groups->assign(userId: 5, companyId: 0, groupId: 2);

        self::assertSame(['tickets:read'], $this->resolver->forMembership(5, new Membership(7, [])));
        self::assertSame(['tickets:read'], $this->resolver->forMembership(5, new Membership(9, [])));
    }

    public function test_a_per_person_deny_removes_a_group_right(): void
    {
        $this->groups->add(new Group(1, Group::PLATFORM, 'buchhaltung', 'Buchhaltung', null, ['invoices:read', 'invoices:pay']));
        $this->groups->assign(userId: 5, companyId: 7, groupId: 1);

        $result = $this->resolver->forMembership(
            5,
            new Membership(7, [], false, [], null, ['invoices:pay']),
        );

        self::assertSame(['invoices:read'], $result);
    }

    public function test_the_company_ceiling_is_applied_when_resolving(): void
    {
        $this->policies->set(new CompanyPolicy(7, null, ['tickets:read']));
        $this->groups->add(new Group(1, Group::PLATFORM, 'buchhaltung', 'Buchhaltung', null, ['invoices:pay']));
        $this->groups->assign(userId: 5, companyId: 7, groupId: 1);

        $result = $this->resolver->forMembership(5, new Membership(7, ['tickets:read', 'wiki:write']));

        self::assertSame(['tickets:read'], $result);
    }

    public function test_a_per_user_ceiling_overrides_the_company_one(): void
    {
        $this->policies->set(new CompanyPolicy(7, null, ['tickets:read', 'invoices:read']));

        $result = $this->resolver->forMembership(
            5,
            new Membership(7, ['tickets:read', 'invoices:read'], false, [], ['invoices:read']),
        );

        self::assertSame(['invoices:read'], $result);
    }

    // --- the delegation grant ---------------------------------------------

    public function test_the_admin_flag_is_false_without_the_company_grant(): void
    {
        // A company nobody configured cannot be administered from inside, so
        // the stored flag confers nothing. Promoting someone before switching
        // the company on is the operational mistake this catches.
        self::assertFalse($this->resolver->adminFor(new Membership(7, [], isCompanyAdmin: true)));
    }

    public function test_the_admin_flag_survives_when_the_company_is_switched_on(): void
    {
        $this->policies->allowDelegation(7);

        self::assertTrue($this->resolver->adminFor(new Membership(7, [], isCompanyAdmin: true)));
    }

    public function test_the_grant_alone_does_not_make_anyone_an_admin(): void
    {
        $this->policies->allowDelegation(7);

        self::assertFalse($this->resolver->adminFor(new Membership(7, [], isCompanyAdmin: false)));
    }

    public function test_effective_returns_a_membership_with_both_resolved(): void
    {
        $this->policies->allowDelegation(7);
        $this->groups->add(new Group(1, Group::PLATFORM, 'g', 'G', null, ['invoices:read']));
        $this->groups->assign(userId: 5, companyId: 7, groupId: 1);

        $resolved = $this->resolver->effective(5, new Membership(7, ['tickets:read'], isCompanyAdmin: true));

        self::assertSame(['tickets:read', 'invoices:read'], $resolved->permissions);
        self::assertTrue($resolved->isCompanyAdmin);
        // The stored decisions ride along untouched — the editor still has to
        // show what was set, not only what came out.
        self::assertSame(7, $resolved->companyId);
    }

    // --- the regression guard ---------------------------------------------

    public function test_an_ISSUED_TOKEN_carries_the_group_rights(): void
    {
        // The assertion that would have failed for the whole first release.
        // Anything that resolves a membership only inside the resolver's own
        // unit tests proves nothing: what matters is that the ISSUER uses it.
        $jwt = self::jwt();

        $this->groups->add(new Group(1, Group::PLATFORM, 'buchhaltung', 'Buchhaltung', null, ['invoices:read']));
        $this->groups->assign(userId: 5, companyId: 7, groupId: 1);

        $user = new AppUser(
            5,
            'a@b.test',
            'A',
            false,
            7,
            [],
            'active',
            'hash',
            memberships: [new Membership(7, ['tickets:read'])],
        );

        $issued = $jwt->issueForUser($user, $this->resolver->forUser(5));

        self::assertSame(
            ['tickets:read', 'invoices:read'],
            self::firstCompany($jwt, $issued['token'])['permissions'],
        );
    }

    public function test_an_ISSUED_TOKEN_drops_the_admin_flag_without_the_grant(): void
    {
        $jwt = self::jwt();

        $user = new AppUser(
            5,
            'a@b.test',
            'A',
            false,
            7,
            [],
            'active',
            'hash',
            memberships: [new Membership(7, [], isCompanyAdmin: true)],
        );

        $token = $jwt->issueForUser($user, $this->resolver->forUser(5))['token'];
        self::assertFalse(self::firstCompany($jwt, $token)['admin']);

        // …and comes back the moment the company is switched on.
        $this->policies->allowDelegation(7);
        $token = $jwt->issueForUser($user, $this->resolver->forUser(5))['token'];
        self::assertTrue(self::firstCompany($jwt, $token)['admin']);
    }
}
