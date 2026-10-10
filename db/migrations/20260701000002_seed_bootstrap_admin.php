<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Seeds a single bootstrap admin so a freshly-migrated install can be set up
 * without SSH (the Plesk model): migrate, log in with the documented default,
 * and you're immediately forced to choose a real password.
 *
 * Safe + idempotent:
 *   - runs ONLY when no admin (is_admin = 1) exists yet, so it never touches
 *     an established install or clobbers a real admin;
 *   - the seeded row carries must_change_password = 1, so the default
 *     credential is useless until the operator sets their own password.
 *
 * Credentials are env-overridable (set these in the host .env BEFORE the first
 * migrate to avoid the public default ever existing):
 *   ADMIN_BOOTSTRAP_EMAIL     (default: admin@tracht-digital.de)
 *   ADMIN_BOOTSTRAP_PASSWORD  (default: tds-setup-admin)
 */
final class SeedBootstrapAdmin extends AbstractMigration
{
    private const DEFAULT_EMAIL = 'admin@tracht-digital.de';
    private const DEFAULT_PASSWORD = 'tds-setup-admin';

    public function up(): void
    {
        $existingAdmins = (int) $this->fetchRow('SELECT COUNT(*) AS c FROM app_user WHERE is_admin = 1')['c'];
        if ($existingAdmins > 0) {
            $this->getOutput()->writeln('  <comment>seed_bootstrap_admin: admin already exists — skipping</comment>');
            return;
        }

        $email = strtolower(trim($this->env('ADMIN_BOOTSTRAP_EMAIL', self::DEFAULT_EMAIL)));
        $password = $this->env('ADMIN_BOOTSTRAP_PASSWORD', self::DEFAULT_PASSWORD);

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $email = self::DEFAULT_EMAIL;
        }

        // If that email is already taken (e.g. a customer login), don't seed —
        // promote-to-admin is the create-admin script's job, not this seed.
        $taken = $this->fetchRow(
            'SELECT id FROM app_user WHERE email = ' . $this->getAdapter()->getConnection()->quote($email) . ' LIMIT 1'
        );
        if ($taken !== false && $taken !== null && isset($taken['id'])) {
            $this->getOutput()->writeln('  <comment>seed_bootstrap_admin: email already present — skipping</comment>');
            return;
        }

        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if ($hash === false) {
            throw new \RuntimeException('seed_bootstrap_admin: password hashing failed');
        }

        $conn = $this->getAdapter()->getConnection();
        $this->execute(
            'INSERT INTO app_user '
            . '(email, password_hash, name, is_admin, customer_id, permissions, status, must_change_password, created_at, updated_at) '
            . 'VALUES ('
            . $conn->quote($email) . ', '
            . $conn->quote($hash) . ", "
            . "'Setup-Admin', 1, NULL, '[]', 'active', 1, NOW(), NOW())"
        );

        $usingDefault = $password === self::DEFAULT_PASSWORD;
        $this->getOutput()->writeln("  <info>seed_bootstrap_admin: created admin {$email}</info>");
        if ($usingDefault) {
            $this->getOutput()->writeln('  <comment>  default password: ' . self::DEFAULT_PASSWORD . ' — you must change it on first login</comment>');
        }
    }

    public function down(): void
    {
        // Only remove the seeded row if it still carries the forced-change flag
        // (i.e. it was never used to set a real password).
        $this->execute(
            "DELETE FROM app_user WHERE name = 'Setup-Admin' AND is_admin = 1 AND must_change_password = 1"
        );
    }

    /**
     * Env reader with the safe `?? false` pattern (never `?? getenv() ?: ''`,
     * which clobbers falsy values — the trap documented across these APIs).
     */
    private function env(string $key, string $default): string
    {
        $v = $_ENV[$key] ?? false;
        if ($v === false) {
            $v = getenv($key);
        }
        return ($v === false || $v === '') ? $default : (string) $v;
    }
}
