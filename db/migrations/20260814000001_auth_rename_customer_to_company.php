<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * `customer` → `company`, physically.
 *
 * There is no separate "Kunde" PERSON in this system: there is one `app_user`,
 * and a company row is a **Firma** a user may optionally belong to. The word
 * "customer" here only ever meant the company, and having both words in the
 * schema is what made the product look like it had two kinds of people when it
 * never did.
 *
 * ### Renames, not copies
 *
 * `renameTable`/`renameColumn` keep the rows and their ids, so every pointer
 * survives: `app_user_company.company_id` still names the same companies, and
 * the ids in a live JWT still resolve. That is what makes this safe to run
 * while sessions are open.
 *
 * ### What this does NOT do
 *
 * The `customer_id` **JWT claim** and the `X-Act-As-Customer` **header** are
 * renamed in code, not here, and both spellings stay accepted for one release
 * (see `RefreshAction` / `JwtService` and tds-core-frontend-api's
 * `JwtUserContext`). Tokens already issued keep working until they expire —
 * an hour — which is why the schema can move ahead of them.
 *
 * The stored permission STRINGS (`customers:read` → `companies:read`) are a
 * data change and live in their own migration, after the groups exist.
 *
 * Class prefixed `Auth*` with the file name mapped to it: the gateway loads
 * every service's migrations into one process with one shared phinxlog.
 */
final class AuthRenameCustomerToCompany extends AbstractMigration
{
    public function change(): void
    {
        // The membership table.
        //
        // MySQL's `CHANGE COLUMN` carries the indexes over, so the unique
        // constraint keeps working — but the index KEEPS ITS OLD NAME
        // (`uniq_user_customer`). That is left alone deliberately: an index
        // name is internal, and dropping + re-adding a UNIQUE index to relabel
        // it opens a window with no uniqueness for the sake of cosmetics.
        $this->table('app_user_customer')
            ->renameColumn('customer_id', 'company_id')
            ->update();

        $this->table('app_user_customer')->rename('app_user_company')->update();

        // The denormalised primary membership on the user row.
        $this->table('app_user')
            ->renameColumn('customer_id', 'company_id')
            ->update();

        // Sessions record which company the token was issued for.
        $this->table('session')
            ->renameColumn('customer_id', 'company_id')
            ->update();
    }
}
