# Language: SQL

## Scope
- Covers: SQL written inside the database: stored procedures, functions, triggers, views, policies, grants and migrations. Dialects: PostgreSQL 12 to 17 (PL/pgSQL), MySQL 8 and MariaDB 10/11, SQL Server 2016+ (T-SQL), SQLite 3.
- Common frameworks and tools: migration tools (Flyway, Liquibase, Alembic, Rails and Django migrations, EF migrations), API layers that expose database functions directly (for example PostgREST), dbt (Jinja in SQL), client tools (`psql`, `mysql`, `sqlcmd`, `sqlite3`).
- Application-side query building belongs to the language files and to `injection`. This file covers what the database code itself does.

## Entry points
Input reaches SQL code through parameters, rows and the caller's identity.

- **Routines:** `CREATE [OR REPLACE] FUNCTION|PROCEDURE`, `CREATE PROC`. Callers are every role with `EXECUTE`. In PostgreSQL, `PUBLIC` has `EXECUTE` on new functions unless revoked. Functions in schemas that an API layer exposes are public endpoints.
- **Triggers:** `CREATE TRIGGER ... EXECUTE FUNCTION` (PostgreSQL 11+; `EXECUTE PROCEDURE` before), MySQL and SQL Server triggers. Input is the row. Any principal that can write the table controls it.
- **Views and policies:** `CREATE VIEW`, `CREATE POLICY`, `CREATE SECURITY POLICY`. The caller's query reaches them.
- **Migrations:** `V1__x.sql`, `changelog.xml`, `migrations/*.sql`, `db/migrate`. They run at deploy with high rights. Input is template variables, environment values and data in tables.
- **Client-side commands in `.sql` files:** `psql` meta-commands (`\!`, `\copy`, `\i`, `\gexec`) and variables (`:name`, `:'name'`, `:"name"`), `sqlcmd` variables `$(name)` (pasted as text), MySQL client `source` and `\!`.
- **Bulk load and file features:** `COPY ... FROM`, `LOAD DATA [LOCAL] INFILE`, `BULK INSERT`, `.import`.
- **Grants and roles:** `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES`, `CREATE ROLE|USER`, `ALTER ROLE ... SET`, `EXECUTE AS`.
- **Untrusted database files:** SQLite files from users are input.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| `injection` | PostgreSQL `EXECUTE 'text' \|\| param`; MySQL `PREPARE s FROM CONCAT(...)`; T-SQL `EXEC('...' + @p)` | PostgreSQL `EXECUTE format('... %I ... $1', ident) USING val`; MySQL `PREPARE` with `?` and `EXECUTE ... USING`; T-SQL `sp_executesql @sql, N'@id int', @id = @id` | Identifiers need `%I`, `quote_ident` or `QUOTENAME`, plus an allow-list. `QUOTENAME` returns NULL for input over 128 characters. |
| `injection` | `LIKE` with user text, `ORDER BY` from input, `LIMIT` from input | `ESCAPE` clause, allow-listed columns, integer casts | `%` and `_` are wildcards. |
| `injection` | Second-order: `EXECUTE (SELECT query FROM t ...)`, stored SQL text run later | Do not store executable SQL from users | Data written by one path runs in another. |
| `authz` | `SECURITY DEFINER` (PostgreSQL), `SQL SECURITY DEFINER` and `DEFINER=` (MySQL), `EXECUTE AS OWNER`/`SELF` (SQL Server) | `SECURITY INVOKER` where possible; if definer, fix `search_path` and check the caller inside | MySQL routines and views default to `SQL SECURITY DEFINER`. |
| `authz` | PostgreSQL views (run as owner and bypass row-level security), materialised views | `WITH (security_invoker = true)` (PostgreSQL 15+), policies on the view | A materialised view holds data computed at refresh time. Reads do not apply the base table's policies. |
| `authz` | Row-level security: `ENABLE ROW LEVEL SECURITY` without `FORCE`, `BYPASSRLS`, owner connections, `USING` without `WITH CHECK` on write paths | `FORCE ROW LEVEL SECURITY`, separate owner and application roles, restrictive policies | Table owners and superusers skip policies unless forced. Foreign key checks and unique violations can leak existence. |
| `authz` | `GRANT ALL`, `TO PUBLIC`, `WITH GRANT OPTION`, `'user'@'%'`, `GRANT ... ON *.*`, SQL Server `db_owner`, `sysadmin`, `CONTROL`, `IMPERSONATE`, enabled `guest` | Least privilege per role, `REVOKE EXECUTE ... FROM PUBLIC` | The application should not connect as the owner. |
| `authz` | Session variables as identity: `current_setting('app.user', true)`, `SESSION_CONTEXT`, MySQL `@user_var` | `SET LOCAL` inside a transaction, `sp_set_session_context ... @read_only = 1` | A session-level `SET` on a pooled connection leaks to the next caller. |
| `authn` | `CREATE ROLE ... PASSWORD 'literal'`, `IDENTIFIED BY 'literal'`, seed admin rows, MD5 password storage, `mysql_native_password` | `scram-sha-256` (PostgreSQL 14+ default), `caching_sha2_password` | MySQL deprecated `mysql_native_password` in 8.0.34 and removed it in 9.0. |
| `crypto` | `MD5()`, `SHA1()`, `HASHBYTES('MD5'\|'SHA1')`, `crypt()` with `gen_salt('md5')`, `AES_ENCRYPT` (default ECB), `random()`, `RAND()`, `UUID()`, `NEWID()` for tokens | `gen_random_bytes`, `gen_random_uuid` (core in PostgreSQL 13), `crypt()` with `gen_salt('bf')`, `CRYPT_GEN_RANDOM`, application-side password hashing | MySQL `block_encryption_mode` defaults to `aes-128-ecb`. |
| `filesystem-process` | `COPY ... FROM\|TO PROGRAM`, `pg_read_file`, `pg_read_binary_file`, `lo_import`, `lo_export`, `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE()`, `xp_cmdshell`, `BULK INSERT`, `OPENROWSET`, `sp_OACreate`, SQLite `ATTACH DATABASE`, `VACUUM INTO` | Do not grant. Keep features off. | `ATTACH` with an injected path creates or opens files. |
| `outbound-network` | `dblink`, `postgres_fdw`, `CREATE SERVER`, MySQL `FEDERATED`, SQL Server linked servers, `OPENQUERY`, `xp_dirtree` with a UNC path | Allow-listed servers, no user-chosen targets | A UNC path can send credentials to a remote host. |
| `input-parsing` | `jsonb_populate_record`, `OPENJSON ... WITH`, MySQL `JSON_TABLE` (8.0.4+), `OPENXML`, `COPY` of untrusted CSV, untrusted SQLite files | Explicit column lists, type checks, `PRAGMA trusted_schema = OFF` and `SQLITE_DBCONFIG_DEFENSIVE` for SQLite files you did not create | |
| `input-parsing` | Collation and case: unique names with `_ci` collations, `utf8mb4_0900_ai_ci` (MySQL 8 default), SQL Server `CI_AS`, SQLite `LIKE` and `NOCASE` | Normalise identifiers in one place, unique index on the normalised value | Accent-insensitive collations make `a` equal `á`. Padding collations ignore trailing spaces. |
| `data-lifecycle` | Soft-delete flags not in views, `TRUNCATE`, audit triggers, backups, `SELECT *` in views, temp tables | Views that apply the delete flag, explicit column lists | A new sensitive column appears in every `SELECT *` consumer after a migration. |
| `logging-privacy` | `RAISE NOTICE` with data, `general_log` (MySQL), `log_statement`, binary logs, audit triggers that store secrets, error `DETAIL` text | Redact, limit logging of parameters (`log_parameter_max_length`, PostgreSQL 13+) | |
| `resource-exhaustion` | Recursive CTEs, `generate_series`, cross joins, `LIKE '%x%'` scans, regex operators (`~`, `REGEXP`), `pg_sleep`, `WAITFOR`, `SLEEP()` | `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` (PostgreSQL), `max_execution_time` (MySQL, SELECT only), `OPTION (MAXRECURSION n)`, `cte_max_recursion_depth` (MySQL) | |
| `financial` | `FLOAT`, `REAL`, `DOUBLE`, PostgreSQL `money`, `ROUND` rules, subtract on unsigned | `NUMERIC(p,s)` or `DECIMAL(p,s)` | MySQL in non-strict mode truncates or clamps values. |
| `concurrency` | Read then write on balances or counters, check-then-insert, `MERGE` (SQL Server), `INSERT IGNORE`, `INSERT OR REPLACE`, `REPLACE INTO` | `UPDATE ... SET x = x - :n WHERE x >= :n` and check the row count, unique indexes, `ON CONFLICT` | See the concurrency section. |
| `supply-chain` | `CREATE EXTENSION`, `LOAD`, third-party SQL packages, edited applied migrations, Flyway `ignoreMigrationPatterns`, Liquibase `runOnChange` | Pinned versions, checksum validation | Flyway validates checksums by default (`validateOnMigrate`). |
| `secrets-config` | Literal passwords in SQL, `skip-grant-tables`, `trust` in `pg_hba.conf`, `sa`, `TRUSTWORTHY ON` | Secret store, per-role credentials | |
| `business-logic` | `CHECK` constraints that pass NULL, triggers that skip rows, `session_replication_role = replica` | `NOT NULL` plus `CHECK`, constraints instead of triggers | |
| `sandbox` | Untrusted procedural languages: `plpython3u`, `plperlu`, `pltclu`, `LANGUAGE c`, SQL Server CLR assemblies, MySQL `CREATE FUNCTION ... SONAME` | Trusted languages, no custom code in the database | Creating them needs high rights. Check who has them. |

## Language traps

- **NULL logic.** A comparison with NULL is unknown, not false.
  - `WHERE owner_id <> :uid` excludes rows with NULL owners. Check whether the intended rule requires that result. For null-safe inequality, use PostgreSQL `a IS DISTINCT FROM b`, MySQL `NOT (a <=> b)` or SQLite `a IS NOT b`. MySQL `<=>` and SQLite `IS` mean null-safe equality.
  - `WHERE id NOT IN (SELECT blocked_id FROM blocks)` can exclude every row when the subquery contains NULL. Use a correlated `NOT EXISTS` when that matches the intended rule. Test NULL values on both sides.
- **CHECK passes NULL.** A `CHECK (price >= 0)` accepts NULL. Add `NOT NULL`.
- **UNIQUE and NULL.** PostgreSQL, MySQL and SQLite allow many NULLs in a unique column. SQL Server allows one. PostgreSQL 15 adds `NULLS NOT DISTINCT`.
- **Dynamic SQL.** Wrong: `EXECUTE 'SELECT * FROM ' || tbl`. Right: `EXECUTE format('SELECT * FROM %I WHERE id = $1', tbl) USING id`, after an allow-list check of `tbl`.
- **Search path.** A PostgreSQL `SECURITY DEFINER` function without `SET search_path` resolves names through the caller's path. A caller can place an object with the same name earlier in the path.
  - For a `SECURITY DEFINER` function, set a fixed path of trusted schemas with `pg_temp` explicitly last, for example `SET search_path = pg_catalog, app, pg_temp`. Confirm that untrusted users cannot create objects in `app`. Omission of `pg_temp` can search it first. Schema-qualify names and restrict `EXECUTE` grants, for example `REVOKE ALL ON FUNCTION f() FROM PUBLIC` before granting intended callers access.
- **Default function rights.** PostgreSQL grants `EXECUTE` on new functions to `PUBLIC`. PostgreSQL 15 removed `CREATE` on the `public` schema from `PUBLIC` by default. Older versions keep it.
- **Definer rights in SQL Server.** Ownership chaining skips permission checks on objects with the same owner. Dynamic SQL breaks the chain. `TRUSTWORTHY ON` with a `db_owner` user can lead to `sysadmin`.
- **Triggers and rights.** PostgreSQL triggers run as the caller unless the function is `SECURITY DEFINER`. MySQL triggers use the definer.
- **Row-level security (PostgreSQL).** Default deny applies when RLS is on and no policy exists. Multiple permissive policies combine with OR. `AS RESTRICTIVE` policies combine with AND. If `WITH CHECK` is missing, `USING` is used for new rows. Functions marked `LEAKPROOF` may run before the policy filter. Check whether that designation is valid; do not assume an arbitrary user function can run before RLS.
- **Row-level security elsewhere.** SQL Server uses `CREATE SECURITY POLICY` with filter and block predicates. MySQL has none. Teams build it with views and `CURRENT_USER()`. SQLite has no users or grants. The application is the only control. `sqlite3_set_authorizer` is a host API.
- **Implicit casts.** MySQL compares a string column with a number by casting the string to a number. Wrong: `WHERE token = 0` (matches non-numeric tokens). Right: bind the right type. SQL Server converts `varchar` and `nvarchar` implicitly. SQLite columns have type affinity: only `STRICT` tables (3.37+) enforce types.
- **Truncation.** MySQL without strict `sql_mode` cuts long strings and clamps numbers. A long name that is cut can equal an existing name.
- **Errors that continue.** PostgreSQL `EXCEPTION WHEN OTHERS THEN RETURN true`, MySQL `DECLARE CONTINUE HANDLER FOR SQLEXCEPTION`, empty T-SQL `CATCH`. Each one turns a failed check into success. T-SQL `XACT_ABORT` is OFF by default, so an error does not roll back the transaction.
- **DDL and transactions.** MySQL DDL commits implicitly. A failed migration leaves partial changes. PostgreSQL DDL is transactional.
- **Time.** PostgreSQL `now()` is the transaction start time. Use `clock_timestamp()` for the real time. `timestamp` has no zone. MySQL `TIMESTAMP` ends in 2038.
- **Overflow.** MySQL `UNSIGNED` subtraction errors unless `NO_UNSIGNED_SUBTRACTION`. `ABS` of the minimum integer fails or overflows.

## Deserialisation and reflection

- **Data to code.** `EXECUTE`, `EXEC(@sql)`, `sp_executesql` and `PREPARE` on text read from a table. `DO $$ ... $$` blocks built from input.
- **Type-driven loading.** `jsonb_populate_record`, `OPENJSON ... WITH`, `JSON_TABLE` and `json_each` map attacker keys to columns. Use explicit field lists.
- **Name resolution.** `'x'::regclass`, `to_regclass`, `format('%I')` and unqualified names resolve through `search_path`. Schema-qualify.
- **Loading code.** `CREATE EXTENSION`, `LOAD`, `shared_preload_libraries`, `session_preload_libraries`, `dynamic_library_path` (PostgreSQL); `INSTALL PLUGIN`, `CREATE FUNCTION ... SONAME` and `plugin_dir` (MySQL); `CREATE ASSEMBLY` and `clr enabled` (SQL Server); `load_extension` and `sqlite3_enable_load_extension` (SQLite; off by default). Untrusted languages (`plpython3u`, `plperlu`, `pltclu`) run with the server's rights.
- **Client-side execution.** A `.sql` file run with `psql` can run `\!`. A `.sql` file run with `mysql` can run `\!` or `system`. A server that sends `LOAD DATA LOCAL` requests can read client files. `local_infile` defaults to off in MySQL 8.0.
- **Untrusted SQLite files.** The schema can contain views, triggers and functions. Set `PRAGMA trusted_schema = OFF` (3.31+), use `SQLITE_DBCONFIG_DEFENSIVE` (3.26+), and run `PRAGMA integrity_check`.

## Concurrency

- **Default isolation.** PostgreSQL: read committed. MySQL InnoDB: repeatable read. SQL Server: read committed with locks (snapshot only if `READ_COMMITTED_SNAPSHOT` is on). SQLite: serialised writes, with `SQLITE_BUSY` on contention.
- **Lost update.** `SELECT balance` then `UPDATE balance = :new` races. Use an atomic `UPDATE` with a guard and check the row count, or `SELECT ... FOR UPDATE` (SQL Server: `UPDLOCK, HOLDLOCK`).
- **Check then insert.** A `SELECT` then `INSERT` for "one per user" needs a unique index. Handle the violation.
- **Upserts.** PostgreSQL `INSERT ... ON CONFLICT`, MySQL `ON DUPLICATE KEY UPDATE`. `MERGE` in SQL Server has known race traps; add `HOLDLOCK`. MySQL `INSERT IGNORE` also hides other errors and truncations. SQLite `INSERT OR REPLACE` and MySQL `REPLACE INTO` delete then insert, which fires cascades and loses unspecified columns.
- **One-time values.** Consume a token with `UPDATE ... SET used = true WHERE id = :id AND used = false` and check one row changed.
- **Serialisable failures.** PostgreSQL error `40001` needs a retry. Retry loops must not repeat side effects.
- **Queues.** `FOR UPDATE SKIP LOCKED` skips rows silently. A crash between claim and finish loses work or runs it twice.
- **Locks.** PostgreSQL `pg_advisory_xact_lock`. Lock order differences cause deadlocks. A deadlock victim rolls back.

## Build and runtime settings

- **PostgreSQL.** `row_security` (on), `password_encryption` (`scram-sha-256` since 14), `pg_hba.conf` (`trust`, `md5`, wide `host` lines), `listen_addresses`, `shared_preload_libraries`, `log_statement`, `log_parameter_max_length`, `statement_timeout`, `session_replication_role` (`replica` turns off triggers and foreign key enforcement), `default_transaction_read_only`, `allow_system_table_mods`, `ALTER ROLE ... SET`.
- **MySQL and MariaDB.** `sql_mode` (`STRICT_ALL_TABLES`, `ONLY_FULL_GROUP_BY`, `NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`, `PIPES_AS_CONCAT`), `local_infile`, `secure_file_priv`, `general_log`, `log_bin_trust_function_creators`, `skip_name_resolve`, `validate_password` component, `event_scheduler`, `max_connections`, account host `%`. `NO_BACKSLASH_ESCAPES` and client escaping functions can disagree.
- **SQL Server.** `sp_configure` options `xp_cmdshell`, `Ole Automation Procedures`, `clr enabled`, `clr strict security`, `Ad Hoc Distributed Queries`, `cross db ownership chaining`; `TRUSTWORTHY`; mixed-mode authentication and `sa`; `SET XACT_ABORT`, `SET QUOTED_IDENTIFIER`, `SET ANSI_NULLS`; `READ_COMMITTED_SNAPSHOT`; contained database users.
- **SQLite.** `PRAGMA foreign_keys` is off by default for each connection. Also `trusted_schema`, `writable_schema`, `secure_delete` (off by default), `query_only`, `journal_mode`. There is no built-in encryption or authentication. File permissions are the only access control.
- **Migrations.** Run migration and runtime code under different roles. Do not run application traffic as the owner.

## Tools

Run only tools that are installed. This section agrees with `phase-leads.md` section 2.1, which has no SQL row. The multi-language row (Semgrep with local rules, `--metrics=off`) and the secrets row apply. The other tools are extra.

| Tool | Offline-safe command | Notes |
|---|---|---|
| sqlfluff | `sqlfluff lint --dialect postgres --disable-progress-bar migrations/` | Dialects: `postgres`, `mysql`, `tsql`, `sqlite`. It checks syntax and style, not security. Use it to confirm that the file parses. Jinja templating (dbt) needs the templater setting. |
| Syntax by the engine | `sqlite3 :memory: ".read file.sql"`; `psql -X -v ON_ERROR_STOP=1 -f file.sql` against a scratch instance | Runs code. Sandbox rules apply. |
| plpgsql_check | `SELECT * FROM plpgsql_check_function('schema.f(int)');` | PostgreSQL extension. Only if already installed in the scratch instance. |
| pgTAP | `pg_prove -d scratchdb test.sql` | Only if installed. |
| Local engines | `initdb -D "$SCRATCH/pg"`, then `pg_ctl -D "$SCRATCH/pg" start -o "-c listen_addresses='' -c unix_socket_directories=$SCRATCH/sock"` | PostgreSQL on a Unix socket only. MySQL: `mysqld --initialize-insecure --datadir=...` then `--skip-networking --socket=...`. |
| Semgrep | `semgrep --config ./local-rules --metrics=off .` | Never `--config auto`. |
| Secrets | `gitleaks`, `trufflehog --no-verification` | Never verify. |

Never run an injection-testing tool such as `sqlmap` against any database. Never connect to a shared or live database.

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `(?i)\bEXECUTE\b\s*(format\s*\(\|'[^']*'\s*\|\|\|\(\|\w+\s*\|\|)\|PREPARE\s+\w+\s+FROM\s+(CONCAT\|@)\|\bEXEC\s*\(\|\bsp_executesql\b` | Dynamic SQL | Safe if `%I`, `quote_ident`, `QUOTENAME` and an allow-list are used. |
| `(?i)SECURITY\s+DEFINER\|SQL\s+SECURITY\s+DEFINER\|DEFINER\s*=\|EXECUTE\s+AS\s+(OWNER\|SELF)` | Definer rights | Check `SET search_path` and caller checks nearby. |
| `(?i)ROW\s+LEVEL\s+SECURITY\|CREATE\s+POLICY\|FORCE\s+ROW\|SECURITY\s+POLICY\|BYPASSRLS\|security_invoker` | Row-level security map | A table with sensitive data and no hit is a lead. |
| `(?i)\bGRANT\b[^;]*(\bALL\b\|PUBLIC\|WITH\s+GRANT\s+OPTION\|\*\.\*)\|'@'%'\|REVOKE[^;]*PUBLIC` | Broad grants | Development seed files. |
| `(?i)TRUSTWORTHY\|xp_cmdshell\|sp_OACreate\|OPENROWSET\|OPENQUERY\|CREATE\s+ASSEMBLY\|clr\s+enabled` | SQL Server host access | |
| `(?i)COPY[^;]*\b(FROM\|TO)\s+PROGRAM\|pg_read_(binary_)?file\|lo_(import\|export)\|INTO\s+(OUT\|DUMP)FILE\|LOAD_FILE\|LOAD\s+DATA\|BULK\s+INSERT\|ATTACH\s+DATABASE\|load_extension\|VACUUM\s+INTO` | File and host access | |
| `(?m)^\s*\\(!\|gexec\|copy\|i\b)\|^\s*(system\|\\!)\s` | Client-side commands in SQL files | |
| `(?i)LANGUAGE\s+(plpython3?u\|plperlu\|pltclu\|c)\b\|SONAME\|CREATE\s+EXTENSION\|INSTALL\s+PLUGIN` | Code loading | |
| `(?i)WHEN\s+OTHERS\s+THEN\|CONTINUE\s+HANDLER\|XACT_ABORT\|CATCH\s*(--.*)?\s*END` | Error handling that may continue | Read the handler. |
| `(?i)\bCHECK\s*\(\|NOT\s+IN\s*\(\s*SELECT\|<>\s*:?\w+` | NULL traps | Needs a column definition check. |
| `(?i)\b(FLOAT\|REAL\|DOUBLE\|MONEY)\b` | Money type | Non-money columns. |
| `(?i)(password\|passwd\|secret\|token\|api_?key)\s*(=\|:)?\s*'[^']+'\|IDENTIFIED\s+BY\s+'\|PASSWORD\s+'` | Literal secrets | Never copy the value. |
| `(?i)\bmd5\s*\(\|\bsha1\s*\(\|HASHBYTES\s*\(\s*'(MD5\|SHA1)'\|gen_salt\s*\(\s*'(md5\|des)'\|AES_ENCRYPT\|\brandom\s*\(\|\bRAND\s*\(\|\bUUID\s*\(` | Weak crypto and randomness | Non-secret use. |
| `(?i)INSERT\s+IGNORE\|INSERT\s+OR\s+(IGNORE\|REPLACE)\|REPLACE\s+INTO\|ON\s+CONFLICT\|ON\s+DUPLICATE\s+KEY\|\bMERGE\b` | Upsert races and side effects | |
| `(?i)set_config\s*\(\|current_setting\s*\(\|SET\s+(SESSION\s+)?\w+\.\w+\s*=\|SESSION_CONTEXT` | Session variables as identity | `SET LOCAL` is safer. |
| `(?i)PRAGMA\s+(foreign_keys\|trusted_schema\|writable_schema)\|session_replication_role\|DISABLE\s+TRIGGER\|NOCHECK\s+CONSTRAINT` | Safety switches | Test fixtures. |
| `(?i)CREATE\s+(OR\s+REPLACE\s+)?VIEW[^;]*SELECT\s+\*` | Wide views | |

## Verification notes

- **Smallest harness.** A scratch database (see Tools) with dummy tables, two dummy roles (A and B) and a canary table. Wrap each test in a transaction and `ROLLBACK` at the end. Record the server version, since results depend on it.
- **Dynamic SQL.** Call the routine as the lower role. Pass a value that would insert a row into the canary table if concatenated. After the call, assert that the canary table is unchanged. Avoid time-based tests.
- **Definer and search path.** As a low-privilege role, create an object with the same name as one the function uses, in a schema earlier in the path. Call the function and check which object it used.
- **Row-level security.** Table owned by B with a policy. `SET ROLE a` and select, update and insert. Expect zero rows or an error. Test through views, materialised views, `COPY`, foreign key inserts and error messages.
- **Grants.** Query the catalogue (`information_schema`, `pg_proc`, `mysql.db`, `sys.database_permissions`) from the dummy low role to list what it can execute.
- **NULL and constraint traps.** A direct `INSERT` with NULL, and a `SELECT` with NULL in the compared column. Use the target engine. SQLite results do not prove PostgreSQL behaviour.
- **Races.** Two sessions with fixed interleaving (`psql` with `\!`-free scripts and a barrier table, or two `sqlite3` processes). Mark `needs-validation` with a plan if you cannot run it.
- **False positives.** `format('%I')` or `quote_ident` with an allow-listed value. A definer function with a fixed `search_path`, schema-qualified names and an inside caller check. A routine granted only to the owner role. Migrations that only an administrator pipeline runs, with no external variable. `SELECT *` in a view over a table with no sensitive columns.
- **Needs E3.** Definer and search-path claims, row-level security bypass through views or planner behaviour, race claims, collation and implicit cast behaviour, and anything that depends on a server setting not in the repository.
