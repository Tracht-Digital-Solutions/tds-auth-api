<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Seeds the platform group "Vermittler" for the Empfehlungsprogramm
 * (tds-ext-referrals-pkg): the one portal key `referrals:partner`, which shows
 * "Empfehlungen" in the customer portal with the partner's link, referrals and
 * payout data.
 *
 * Like every permission, it applies through a company membership — the JWT
 * carries permissions per company. A partner therefore needs a membership
 * (their own company, or one the operator keeps for partners), and this group
 * assigned there or globally (scope 0).
 *
 * The permission list is a snapshot, not an import, for the reason given in
 * 20260814000004: a migration must not read a moving constant. `INSERT IGNORE`
 * against the unique slug keeps a re-run a no-op.
 */
final class AuthSeedReferralPartnerGroup extends AbstractMigration
{
    public function up(): void
    {
        $conn = $this->getAdapter()->getConnection();
        $this->execute(sprintf(
            'INSERT IGNORE INTO auth_group (company_id, slug, name, description, permissions, is_system)
             VALUES (0, %s, %s, %s, %s, 1)',
            $conn->quote('referral_partner'),
            $conn->quote('Vermittler'),
            $conn->quote('Empfehlungsprogramm: eigener Link, Vermittlungen und Provisionen.'),
            $conn->quote((string) json_encode(['referrals:partner'])),
        ));
    }

    public function down(): void
    {
        $this->execute("DELETE FROM auth_group WHERE company_id = 0 AND is_system = 1 AND slug = 'referral_partner'");
    }
}
