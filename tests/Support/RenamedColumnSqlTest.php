<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use PHPUnit\Framework\TestCase;

/**
 * Static guard against SQL that still names an identifier a migration renamed.
 *
 * The failure this exists for: migration 20260814000001 renamed
 * `session.customer_id` to `company_id`, and `PdoSessionRepository` kept
 * writing the old name. The result was
 *
 *     SQLSTATE[42S22] 1054 Unknown column 'customer_id' in 'field list'
 *
 * on **every successful login** — while a wrong password still returned a
 * clean 401, because it returns before a session is ever recorded. So the login
 * form looked half-working: it rejected bad credentials correctly and answered
 * correct ones with a 500.
 *
 * ### Why the whole test suite was green
 *
 * `PdoSessionRepositoryTest` builds its own `session` table with hand-written
 * DDL, and that DDL still said `customer_id`. The DB-backed tests DO run in CI
 * against a real MariaDB, so this was not a case of a skipped test — the test
 * created the pre-rename schema, asserted against it, and passed. A DB test
 * that invents its own schema only ever tests itself. That is the same trap
 * already recorded for `tds-content-api`'s blog-post repository.
 *
 * This check is the cheap half: it needs no database at all, so it also fires
 * in the environments where `TDS_TEST_DB_DSN` is unset. The expensive half is
 * keeping the hand-written DDL in step with the migrations, which the comment
 * in that suite's `setUp()` now spells out.
 */
final class RenamedColumnSqlTest extends TestCase
{
    private const SRC_DIR = __DIR__ . '/../../src';

    /**
     * Identifiers a migration retired, mapped to what replaced them.
     *
     * Only SQL is checked, so the deliberate survivors are untouched: the
     * `customer_id` JWT claim and the `?customer_id=` query parameter are both
     * kept as deprecated aliases for one release, and `customer_credential` is
     * a table that was never renamed.
     *
     * @var array<string, string>
     */
    private const RETIRED = [
        'app_user_customer' => 'app_user_company',
        'customer_id' => 'company_id',
    ];

    public function testNoSqlReferencesARenamedIdentifier(): void
    {
        $offenders = [];

        foreach ($this->phpFiles(self::SRC_DIR) as $file) {
            $source = file_get_contents($file) ?: '';

            foreach ($this->sqlLiterals($source) as $literal) {
                foreach (self::RETIRED as $old => $new) {
                    if (preg_match('/\b' . preg_quote($old, '/') . '\b/', $literal) === 1) {
                        $offenders[] = sprintf(
                            '%s: SQL names the renamed identifier "%s" (now "%s"): %s',
                            basename($file),
                            $old,
                            $new,
                            trim($literal),
                        );
                    }
                }
            }
        }

        self::assertSame([], $offenders, implode("\n", $offenders));
    }

    /**
     * String literals that are themselves a piece of SQL.
     *
     * Matching only literals carrying a SQL keyword is what keeps this precise:
     * these repositories build statements by concatenation, and the surrounding
     * PHP legitimately uses `customer_id` as an array key for the deprecated
     * claim. A literal with `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`FROM`/`JOIN`
     * in it is SQL and nothing else.
     *
     * @return list<string>
     */
    private function sqlLiterals(string $source): array
    {
        // Single- and double-quoted literals, plus heredoc/nowdoc bodies.
        $pattern = '/\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*"|<<<[\'"]?(\w+)[\'"]?\R(.*?)\R\s*\1/s';
        preg_match_all($pattern, $source, $matches, PREG_SET_ORDER);

        $out = [];
        foreach ($matches as $match) {
            $literal = $match[2] ?? '';
            if ($literal === '') {
                $literal = trim($match[0], '\'"');
            }

            if (preg_match('/\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|JOIN)\b/i', $literal) === 1) {
                $out[] = $literal;
            }
        }

        return $out;
    }

    /** @return list<string> */
    private function phpFiles(string $dir): array
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
        );

        $files = [];
        foreach ($iterator as $entry) {
            /** @var \SplFileInfo $entry */
            if ($entry->isFile() && $entry->getExtension() === 'php') {
                $files[] = $entry->getPathname();
            }
        }
        sort($files);

        return $files;
    }
}
