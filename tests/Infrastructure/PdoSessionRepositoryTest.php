<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\PdoSessionRepository;

/**
 * Integration test against MariaDB. Set TDS_TEST_DB_DSN (+ user/pass) to
 * run, skipped otherwise.
 */
final class PdoSessionRepositoryTest extends TestCase
{
    private PDO $pdo;
    private PdoSessionRepository $repo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run session repository tests.');
        }

        $this->pdo = new PDO(
            $dsn,
            getenv('TDS_TEST_DB_USER') ?: null,
            getenv('TDS_TEST_DB_PASS') ?: null,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ],
        );

        $this->pdo->exec('DROP TABLE IF EXISTS session');
        // `company_id`, matching migration 20260814000001. THIS is why the
        // rename shipped with a broken login and a green CI: the DDL below is
        // hand-written, so it kept the pre-rename column and every assertion
        // here passed against a table production does not have. The repository
        // was still writing `customer_id`, which meant a 500 on every correct
        // password while a wrong one returned a clean 401. Any column this
        // suite invents has to be the migrated one — a DB test that builds its
        // own schema only ever tests itself.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE session (
              jti VARCHAR(36) NOT NULL,
              company_id INT NULL,
              user_id INT NULL,
              admin TINYINT(1) NOT NULL DEFAULT 0,
              expires_at DATETIME NOT NULL,
              -- DATETIME(6), matching migration 20260805000003. The DDL here is
              -- hand-written rather than migrated, so it has to be kept in step:
              -- at 1-second resolution this suite would pass while production
              -- ordering stayed broken, because record() writes NOW(6).
              created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
              revoked_at DATETIME NULL,
              PRIMARY KEY (jti),
              KEY idx_company_id (company_id),
              KEY idx_user_id (user_id),
              KEY idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $this->repo = new PdoSessionRepository($this->pdo);
    }

    public function test_record_then_isRevoked_returns_false(): void
    {
        $this->repo->record('jti-1', null, true, time() + 900);

        self::assertFalse($this->repo->isRevoked('jti-1'));
    }

    public function test_unknown_jti_treated_as_revoked(): void
    {
        self::assertTrue($this->repo->isRevoked('does-not-exist'));
    }

    public function test_revoke_marks_session_revoked(): void
    {
        $this->repo->record('jti-2', 42, false, time() + 900);
        $this->repo->revoke('jti-2');

        self::assertTrue($this->repo->isRevoked('jti-2'));
    }

    public function test_revoke_idempotent_for_already_revoked(): void
    {
        $this->repo->record('jti-3', null, true, time() + 900);
        $this->repo->revoke('jti-3');
        $this->repo->revoke('jti-3');

        self::assertTrue($this->repo->isRevoked('jti-3'));
    }

    public function test_record_persists_company_id_and_admin_flag(): void
    {
        $this->repo->record('jti-4', 99, false, time() + 900);

        $row = $this->pdo->query("SELECT company_id, admin FROM session WHERE jti = 'jti-4'")->fetch();
        self::assertSame(99, (int) $row['company_id']);
        self::assertSame(0, (int) $row['admin']);
    }

    /**
     * The login regression, at the layer that broke: an admin has no company,
     * so `record()` is called with a null company id and nothing else in the
     * statement is exercised by the assertions above. It threw
     * "Unknown column 'customer_id'" for every user, admin or not.
     */
    public function test_record_succeeds_for_a_session_without_a_company(): void
    {
        $this->repo->record('jti-no-company', null, true, time() + 900, 1);

        $row = $this->pdo->query("SELECT company_id, user_id FROM session WHERE jti = 'jti-no-company'")->fetch();
        self::assertNull($row['company_id']);
        self::assertSame(1, (int) $row['user_id']);
    }

    public function test_listed_rows_carry_company_id_and_its_deprecated_alias(): void
    {
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('jti-alias', 77, false, time() + 900, 3);

        $rows = $this->repo->listActiveForUser(3);

        self::assertCount(1, $rows);
        self::assertSame(77, $rows[0]['company_id']);
        // Emitted for one release so readers deployed before the rename keep working.
        self::assertSame(77, $rows[0]['customer_id']);
    }

    public function test_record_persists_user_id(): void
    {
        $this->repo->record('jti-uid', 5, false, time() + 900, 1234);

        $row = $this->pdo->query("SELECT user_id FROM session WHERE jti = 'jti-uid'")->fetch();
        self::assertSame(1234, (int) $row['user_id']);
    }

    public function test_revoke_all_for_user_revokes_every_session(): void
    {
        $this->repo->record('jti-u-a', 5, false, time() + 900, 7);
        $this->repo->record('jti-u-b', 5, false, time() + 900, 7);
        $this->repo->record('jti-other', 5, false, time() + 900, 8);

        $this->repo->revokeAllForUser(7);

        self::assertTrue($this->repo->isRevoked('jti-u-a'));
        self::assertTrue($this->repo->isRevoked('jti-u-b'));
        self::assertFalse($this->repo->isRevoked('jti-other'));
    }

    public function test_list_active_returns_unrevoked_unexpired_sessions(): void
    {
        $this->repo->record('jti-active', 1, false, time() + 900);
        $this->repo->record('jti-revoked', 2, false, time() + 900);
        $this->repo->revoke('jti-revoked');
        // expired
        $this->pdo->exec(
            "INSERT INTO session (jti, company_id, admin, expires_at, created_at) "
            . "VALUES ('jti-expired', 3, 0, '2020-01-01 00:00:00', '2020-01-01 00:00:00')"
        );

        $rows = $this->repo->listActive();

        $jtis = array_column($rows, 'jti');
        self::assertContains('jti-active', $jtis);
        self::assertNotContains('jti-revoked', $jtis);
        self::assertNotContains('jti-expired', $jtis);
    }

    public function test_list_active_respects_limit_and_newest_first(): void
    {
        for ($i = 1; $i <= 3; $i++) {
            $this->repo->record("jti-{$i}", null, true, time() + 900);
        }

        $rows = $this->repo->listActive(limit: 2);

        self::assertCount(2, $rows);
        // Newest first — the last inserted (jti-3) should be at index 0
        self::assertSame('jti-3', $rows[0]['jti']);
    }

    public function test_list_active_orders_same_second_sessions_by_real_recency(): void
    {
        // The regression this exists for: created_at used to be 1-second
        // resolution, so three sessions issued inside the same second tied and
        // the sort fell through to the jti tiebreaker — a random UUIDv4. The
        // order was deterministic but unrelated to recency, which is precisely
        // what "newest first" must not mean. The jtis below are deliberately
        // NOT in ascending order, so a tiebreaker-driven sort cannot pass.
        $this->pdo->exec('DELETE FROM session');
        foreach (['m-zulu', 'm-alpha', 'm-mike'] as $jti) {
            $this->repo->record($jti, null, true, time() + 900);
        }

        $rows = $this->repo->listActive();

        // Insertion order reversed — the last one written comes first.
        self::assertSame(['m-mike', 'm-alpha', 'm-zulu'], array_column($rows, 'jti'));
    }

    public function test_list_active_for_user_scopes_in_SQL(): void
    {
        // The scoping has to happen in the query. If this ever fell back to
        // filtering listActive() in PHP, a self-service caller would be handed
        // every other user's session rows first.
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('mine-1', 7, false, time() + 900, 5);
        $this->repo->record('theirs', 9, false, time() + 900, 6);
        $this->repo->record('mine-2', 7, false, time() + 900, 5);

        $rows = $this->repo->listActiveForUser(5);

        self::assertSame(['mine-2', 'mine-1'], array_column($rows, 'jti'));
    }

    public function test_list_active_for_user_omits_revoked_and_expired(): void
    {
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('live', 7, false, time() + 900, 5);
        $this->repo->record('stale', 7, false, time() - 60, 5);
        $this->repo->record('gone', 7, false, time() + 900, 5);
        $this->repo->revoke('gone');

        $rows = $this->repo->listActiveForUser(5);

        self::assertSame(['live'], array_column($rows, 'jti'));
    }

    public function test_owner_of_identifies_the_session_holder(): void
    {
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('mine', 7, false, time() + 900, 5);

        self::assertSame(5, $this->repo->ownerOf('mine'));
        self::assertNull($this->repo->ownerOf('never-existed'));
    }

    public function test_owner_of_treats_revoked_and_expired_as_gone(): void
    {
        // A self-service revoke proves ownership through this method, and
        // must report "not found" for a session the caller could not have
        // seen in their own list.
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('stale', 7, false, time() - 60, 5);
        $this->repo->record('gone', 7, false, time() + 900, 5);
        $this->repo->revoke('gone');

        self::assertNull($this->repo->ownerOf('stale'));
        self::assertNull($this->repo->ownerOf('gone'));
    }

    public function test_owner_of_returns_null_for_a_session_with_no_user(): void
    {
        // Legacy admin-token sessions predate `user_id`. They belong to nobody,
        // so nobody may revoke them through the self-service route.
        $this->pdo->exec('DELETE FROM session');
        $this->repo->record('legacy', null, true, time() + 900);

        self::assertNull($this->repo->ownerOf('legacy'));
    }
}
