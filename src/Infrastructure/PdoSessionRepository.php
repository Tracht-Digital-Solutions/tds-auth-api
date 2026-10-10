<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\SessionRepository;

final class PdoSessionRepository implements SessionRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function record(string $jti, ?int $companyId, bool $admin, int $expiresAtUnix, ?int $userId = null): void
    {
        $stmt = $this->pdo->prepare(
            // `company_id`, not `customer_id` — migration 20260814000001 renamed
            // the column. This statement kept the old name and so threw
            // "Unknown column 'customer_id'" on EVERY successful login, while a
            // wrong password still returned a clean 401 because it never got
            // this far. That asymmetry is the whole signature of the bug: the
            // login form reported "E-Mail oder Passwort falsch" correctly and
            // answered a CORRECT password with a 500.
            //
            // NOW(6), not NOW(): the column is DATETIME(6) so that listActive()
            // can order by real recency. NOW() would write `.000000` on every
            // row and silently reinstate the same-second tie this fixed.
            "INSERT INTO session (jti, company_id, user_id, admin, expires_at, created_at) "
            . "VALUES (:jti, :cid, :uid, :admin, FROM_UNIXTIME(:exp), NOW(6))"
        );
        $stmt->execute([
            'jti' => $jti,
            'cid' => $companyId,
            'uid' => $userId,
            'admin' => $admin ? 1 : 0,
            'exp' => $expiresAtUnix,
        ]);
    }

    public function isRevoked(string $jti): bool
    {
        $stmt = $this->pdo->prepare(
            "SELECT revoked_at FROM session WHERE jti = :jti LIMIT 1"
        );
        $stmt->execute(['jti' => $jti]);
        $row = $stmt->fetch();
        if ($row === false) {
            return true; // unknown jti — treat as revoked
        }
        return $row['revoked_at'] !== null;
    }

    public function revoke(string $jti): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE session SET revoked_at = NOW() WHERE jti = :jti AND revoked_at IS NULL"
        );
        $stmt->execute(['jti' => $jti]);
    }

    public function revokeAllForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE session SET revoked_at = NOW() WHERE user_id = :uid AND revoked_at IS NULL"
        );
        $stmt->execute(['uid' => $userId]);
    }

    public function listActive(int $limit = 200): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT jti, company_id, admin, expires_at, created_at '
            . 'FROM session '
            . 'WHERE revoked_at IS NULL AND expires_at > NOW() '
            // created_at is DATETIME(6) and written with NOW(6), so this really
            // is newest-first — the promise the method makes. The jti tiebreaker
            // stays as the last resort for an exact microsecond tie, which keeps
            // the ordering total. (It was carrying the whole sort while the
            // column was 1-second resolution, and a UUIDv4 is random, so
            // same-second sessions came back in an order unrelated to recency.)
            . 'ORDER BY created_at DESC, jti DESC '
            . 'LIMIT :lim'
        );
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return self::mapRows($stmt->fetchAll());
    }

    public function listActiveForUser(int $userId, int $limit = 50): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT jti, company_id, admin, expires_at, created_at '
            . 'FROM session '
            . 'WHERE user_id = :uid AND revoked_at IS NULL AND expires_at > NOW() '
            // Same total ordering as listActive(): DATETIME(6) first, jti only
            // as the microsecond-tie breaker.
            . 'ORDER BY created_at DESC, jti DESC '
            . 'LIMIT :lim'
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return self::mapRows($stmt->fetchAll());
    }

    public function ownerOf(string $jti): ?int
    {
        // Revoked and expired sessions deliberately do NOT match: a
        // self-service revoke of one is a no-op the caller should see as
        // "gone", and treating it as found would let the route report success
        // for a session that is not in the list it was picked from.
        $stmt = $this->pdo->prepare(
            'SELECT user_id FROM session '
            . 'WHERE jti = :jti AND revoked_at IS NULL AND expires_at > NOW() LIMIT 1'
        );
        $stmt->execute(['jti' => $jti]);
        $row = $stmt->fetch();

        if (!is_array($row) || $row['user_id'] === null) {
            return null;
        }
        return (int) $row['user_id'];
    }

    /**
     * `GET /admin/sessions` writes these rows to the wire verbatim, so the keys
     * here are public API. The column is `company_id` now, and both spellings
     * are emitted for one release — the same dual-accept the rename uses for
     * the JWT claim and the act-as header, for the same reason: readers of this
     * payload do not all deploy at the same instant.
     *
     * @param list<array<string,mixed>> $rows
     * @return list<array{jti: string, company_id: ?int, customer_id: ?int, admin: bool, expires_at: string, created_at: string}>
     */
    private static function mapRows(array $rows): array
    {
        return array_map(static function (array $r): array {
            $companyId = $r['company_id'] !== null ? (int) $r['company_id'] : null;

            return [
                'jti' => (string) $r['jti'],
                'company_id' => $companyId,
                // Deprecated alias of `company_id`, emitted for ONE release.
                'customer_id' => $companyId,
                'admin' => (bool) $r['admin'],
                'expires_at' => (string) $r['expires_at'],
                'created_at' => (string) $r['created_at'],
            ];
        }, $rows);
    }
}
