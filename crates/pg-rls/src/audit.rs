//! Boot-time invariant checks for tenant isolation.
//!
//! pg-rls's runtime hooks scope each request to a tenant, but if the
//! schema itself is broken the hooks can't help. The cheapest defense is
//! a boot-time scan that refuses to start the app. The audit looks for:
//!
//! - **`policy_rls_off`** — policy written but `ALTER TABLE ... ENABLE
//!   ROW LEVEL SECURITY` forgotten (Postgres ignores the policy entirely)
//! - **`policy_no_force`** — RLS enabled but no `FORCE`, so the table-
//!   owner role (which most apps connect as) bypasses the policy
//! - **`rls_no_policy`** — RLS enabled with zero policies attached
//!   (default-deny — every query returns no rows, every write fails)
//! - **`policy_fail_open`** — `COALESCE(current_setting(...), ...)`
//!   pattern that degrades to "match every row" when the GUC is unset
//! - **`policy_no_guc_reference`** — policy USING expression doesn't
//!   mention `current_setting('<guc>'` at all (`USING (TRUE)`,
//!   `USING (1=1)`, etc.) — every row visible to every tenant
//! - **`tenant_col_no_policy`** — table has the configured tenant
//!   column but no policy at all
//! - **`policy_no_with_check`** — house-rule recommendation: write
//!   policies should have an explicit `WITH CHECK` clause so writes
//!   stay correct if `USING` later changes
//!
//! Two entry points:
//!
//! - [`ensure_isolation`] (default config) / [`crate::Tenancy::ensure_isolation`]
//!   (custom) — run against a live `PgPool` at boot. Returns a [`Report`]
//!   enumerating every finding. Wire into your boot path:
//!
//!   ```no_run
//!   # async fn run(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//!   let report = pg_rls::audit::ensure_isolation(&pool).await?;
//!   if !report.is_clean() {
//!       panic!("RLS invariants broken at boot:\n{report}");
//!   }
//!   # Ok(()) }
//!   ```
//!
//! - [`scan_migrations`] (default config) / [`crate::Tenancy::scan_migrations`]
//!   (custom) — grep `*.sql` under a directory for `CREATE POLICY`
//!   statements that are missing `WITH CHECK`. Cheap, runs in CI without
//!   a database. Catches the bug at code-review time, before it ever
//!   reaches `pg_policy`.
//!
//! ## How to interpret findings
//!
//! The audit intentionally mixes findings with different severities:
//!
//! - **Likely leak or bypass:** `policy_rls_off`, `policy_no_force`,
//!   `policy_fail_open`, `policy_no_guc_reference`
//! - **Likely broken configuration / availability issue:** `rls_no_policy`,
//!   `tenant_col_no_policy`
//! - **House-rule recommendation:** `policy_no_with_check`
//!
//! A strict production boot path will usually fail on the first two
//! groups unconditionally. The last group is a policy-style convention:
//! valuable, but not by itself proof of a leak.
//!
//! ## Known limitations
//!
//! The audit reads `pg_get_expr(polqual, polrelid)` and pattern-matches
//! known-bad shapes. The `policy_no_guc_reference` finder is heuristic:
//! policies that read the GUC indirectly via a SQL function call (e.g.
//! `USING (auth.current_tenant() = tenant_id)` where the function
//! internally calls `current_setting(...)`) won't textually contain the
//! configured GUC name and will be flagged as false positives. Inline
//! the `current_setting` call in the policy expression, or filter the
//! affected rows out of your boot check.
//!
//! ## Schema and column scope
//!
//! By default the audit walks the `public` schema and recognises columns
//! named `tenant_id` as tenant tags. Override either via [`crate::Tenancy`]:
//!
//! ```no_run
//! # async fn run(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//! use pg_rls::Tenancy;
//!
//! let report = Tenancy::new()
//!     .schemas(["app", "data"])
//!     .tenant_column("org_id")
//!     .ensure_isolation(&pool).await?;
//! # let _ = report;
//! # Ok(()) }
//! ```

use crate::config::Tenancy;
use sqlx::PgPool;
use std::fmt;
use std::path::{Path, PathBuf};

/// A table that the audit flagged. Identified by `schema.table`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TableName {
    pub schema: String,
    pub table: String,
}

impl fmt::Display for TableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.schema, self.table)
    }
}

/// A specific RLS policy on a table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyRef {
    pub schema: String,
    pub table: String,
    pub policy: String,
}

impl fmt::Display for PolicyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}::{}", self.schema, self.table, self.policy)
    }
}

/// Findings from a single audit run.
///
/// `is_clean()` is the success condition — every list empty.
/// [`fmt::Display`] renders a human-readable multiline report you can
/// drop straight into a panic message.
///
/// If you want to distinguish "hard fail" findings from house-rule
/// recommendations, treat `policy_no_with_check` separately. The other
/// categories are much stronger signals of either a tenant leak, an RLS
/// bypass, or a schema that will fail in production.
///
/// Marked `#[non_exhaustive]` so adding a finding category later isn't a
/// breaking change. Build with [`Report::default()`] inside this crate;
/// downstream consumers should match against fields rather than
/// destructure with literal struct syntax.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct Report {
    /// Tables with `ENABLE ROW LEVEL SECURITY` set but zero policies
    /// attached. Postgres treats this as default-deny; non-super callers
    /// see no rows and writes fail with an opaque RLS error.
    pub rls_no_policy: Vec<TableName>,

    /// Tables with at least one policy attached but `ENABLE ROW LEVEL
    /// SECURITY` not set. Postgres ignores policies on tables where RLS
    /// is disabled, so the protection is silently skipped — every caller
    /// reads / writes every row regardless of tenant. The classic
    /// "wrote `CREATE POLICY`, forgot `ALTER TABLE ... ENABLE`" bug.
    pub policy_rls_off: Vec<TableName>,

    /// Tables with policies + `ENABLE ROW LEVEL SECURITY` but no
    /// `FORCE ROW LEVEL SECURITY`. Postgres exempts the table owner from
    /// non-FORCE policies, and most apps connect as the table owner
    /// (sqlx migrating in as the role that owns the schema is the common
    /// shape). The policy passes a `naive` test as a different role and
    /// silently leaks in prod under the owner role. The example in this
    /// repo's `examples/rls` crate is exactly this bug.
    pub policy_no_force: Vec<TableName>,

    /// Policies that apply to writes (`INSERT`, `UPDATE`, or `ALL`)
    /// without an explicit `WITH CHECK` clause.
    ///
    /// **Note on semantics:** Postgres falls back to `WITH CHECK = USING`
    /// when `WITH CHECK` is omitted on `ALL` / `INSERT` / `UPDATE`
    /// policies, so the USING predicate gates writes too. A typical
    /// `tenant_id = current_setting(...)` USING expression therefore
    /// still blocks cross-tenant inserts even without an explicit
    /// `WITH CHECK`. This finding is a **house-rule recommendation**, not
    /// a bug catcher: an explicit `WITH CHECK` makes write semantics
    /// independent of any future change to `USING` (e.g. relaxing
    /// `USING` for read filtering would silently widen writes if there's
    /// no separate `WITH CHECK`). Skip this finding by mirroring USING
    /// into an explicit `WITH CHECK` clause, or filter it out of your
    /// boot panic if you don't want to enforce the convention.
    pub policy_no_with_check: Vec<PolicyRef>,

    /// Policies whose USING or WITH CHECK expression matches the
    /// fail-open `COALESCE(current_setting(...), ...)` pattern. Under
    /// fail-open, an unset GUC degrades to "match every row".
    pub policy_fail_open: Vec<PolicyRef>,

    /// Tables with the configured `tenant_column` but no RLS policy.
    /// Suggests either (a) the migration that introduced the column
    /// forgot to add the policy, or (b) the table is intentionally
    /// global and the column name is misleading.
    pub tenant_col_no_policy: Vec<TableName>,

    /// Policies whose USING expression doesn't reference
    /// `current_setting('<configured guc>'` at all — `USING (TRUE)`,
    /// `USING (1=1)`, `USING (visibility = 'public')`, etc. These pass
    /// every row to every tenant.
    ///
    /// **Heuristic, not parser.** Implemented as a substring check on
    /// `pg_get_expr(polqual, polrelid)`. False positives are possible
    /// when a policy reads the GUC via a SQL function call instead of
    /// inlining `current_setting(...)` — e.g. `USING (auth.current_tenant()
    /// = tenant_id)`. If you have such a policy and treat this finding
    /// as a hard fail at boot, either inline the `current_setting` call
    /// or filter the affected rows out of your boot check.
    pub policy_no_guc_reference: Vec<PolicyRef>,
}

impl Report {
    /// `true` when every finding list is empty. The success condition.
    pub fn is_clean(&self) -> bool {
        self.rls_no_policy.is_empty()
            && self.policy_rls_off.is_empty()
            && self.policy_no_force.is_empty()
            && self.policy_no_with_check.is_empty()
            && self.policy_fail_open.is_empty()
            && self.tenant_col_no_policy.is_empty()
            && self.policy_no_guc_reference.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return write!(f, "pg-rls audit: clean.");
        }
        writeln!(f, "pg-rls audit: invariants broken")?;
        if !self.rls_no_policy.is_empty() {
            writeln!(f, "  RLS enabled but no policy attached:")?;
            for t in &self.rls_no_policy {
                writeln!(f, "    - {t}")?;
            }
        }
        if !self.policy_rls_off.is_empty() {
            writeln!(
                f,
                "  policy attached but RLS not enabled (silently ignored):"
            )?;
            for t in &self.policy_rls_off {
                writeln!(f, "    - {t}")?;
            }
        }
        if !self.policy_no_force.is_empty() {
            writeln!(
                f,
                "  policy + RLS but no FORCE (owner-role bypass — see ALTER TABLE ... FORCE):"
            )?;
            for t in &self.policy_no_force {
                writeln!(f, "    - {t}")?;
            }
        }
        if !self.policy_no_with_check.is_empty() {
            writeln!(
                f,
                "  policy without explicit WITH CHECK on a write command (house-rule recommendation):"
            )?;
            for p in &self.policy_no_with_check {
                writeln!(f, "    - {p}")?;
            }
        }
        if !self.policy_fail_open.is_empty() {
            writeln!(f, "  policy uses fail-open COALESCE pattern:")?;
            for p in &self.policy_fail_open {
                writeln!(f, "    - {p}")?;
            }
        }
        if !self.tenant_col_no_policy.is_empty() {
            writeln!(f, "  table has tenant column but no policy attached:")?;
            for t in &self.tenant_col_no_policy {
                writeln!(f, "    - {t}")?;
            }
        }
        if !self.policy_no_guc_reference.is_empty() {
            writeln!(
                f,
                "  policy USING expression doesn't reference current_setting(<guc>) — every row visible to every tenant:"
            )?;
            for p in &self.policy_no_guc_reference {
                writeln!(f, "    - {p}")?;
            }
        }
        Ok(())
    }
}

impl Tenancy {
    /// Run the schema audit against `pool` using this `Tenancy`'s
    /// configured schemas and tenant column. See [`Report`] for what
    /// each finding means.
    pub async fn ensure_isolation(&self, pool: &PgPool) -> sqlx::Result<Report> {
        let _span = tracing::info_span!(
            target: "pg_rls",
            "pg_rls.audit",
            schemas = ?self.schemas,
            tenant_column = self.tenant_column.as_ref(),
        )
        .entered();
        let schemas: Vec<String> = self.schemas.iter().map(|s| s.to_string()).collect();
        let tenant_col = self.tenant_column.as_ref();
        let mut report = Report::default();

        // 1. RLS-on, no policy.
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table"
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND c.relkind = 'r'
              AND c.relrowsecurity
              AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            ORDER BY n.nspname, c.relname
            "#,
        )
        .bind(&schemas)
        .fetch_all(pool)
        .await?;
        report.rls_no_policy = rows
            .into_iter()
            .map(|(schema, table)| TableName { schema, table })
            .collect();

        // 2. Policy attached but RLS not enabled. Postgres ignores the
        //    policy entirely in this state — protection is silently
        //    skipped. Classic "wrote CREATE POLICY, forgot ALTER TABLE
        //    ... ENABLE ROW LEVEL SECURITY" bug.
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table"
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND c.relkind = 'r'
              AND NOT c.relrowsecurity
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            ORDER BY n.nspname, c.relname
            "#,
        )
        .bind(&schemas)
        .fetch_all(pool)
        .await?;
        report.policy_rls_off = rows
            .into_iter()
            .map(|(schema, table)| TableName { schema, table })
            .collect();

        // 3. RLS enabled with policies but no FORCE. Postgres exempts
        //    the table owner unless FORCE is set, and most apps connect
        //    as the table owner — so the policy passes a different-role
        //    test and silently leaks under the owner role.
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table"
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND c.relkind = 'r'
              AND c.relrowsecurity
              AND NOT c.relforcerowsecurity
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            ORDER BY n.nspname, c.relname
            "#,
        )
        .bind(&schemas)
        .fetch_all(pool)
        .await?;
        report.policy_no_force = rows
            .into_iter()
            .map(|(schema, table)| TableName { schema, table })
            .collect();

        // 4. Policy with no explicit WITH CHECK on a write command.
        //    polcmd: 'r'=SELECT, 'a'=INSERT, 'w'=UPDATE, 'd'=DELETE, '*'=ALL
        //
        //    Note: Postgres falls back to `WITH CHECK = USING` when
        //    omitted, so this is a house-rule recommendation rather
        //    than a leak detector. See `Report::policy_no_with_check`
        //    docs for when to act on it vs filter it out.
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table", p.polname::text AS policy
            FROM pg_policy p
            JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND p.polcmd IN ('a', 'w', '*')
              AND p.polwithcheck IS NULL
            ORDER BY n.nspname, c.relname, p.polname
            "#,
        )
        .bind(&schemas)
        .fetch_all(pool)
        .await?;
        report.policy_no_with_check = rows
            .into_iter()
            .map(|(schema, table, policy)| PolicyRef {
                schema,
                table,
                policy,
            })
            .collect();

        // 5. Fail-open COALESCE pattern in USING or WITH CHECK.
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table", p.polname::text AS policy
            FROM pg_policy p
            JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND (
                    COALESCE(pg_get_expr(p.polqual, p.polrelid),      '') ILIKE '%coalesce%current_setting%'
                 OR COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '') ILIKE '%coalesce%current_setting%'
              )
            ORDER BY n.nspname, c.relname, p.polname
            "#,
        )
        .bind(&schemas)
        .fetch_all(pool)
        .await?;
        report.policy_fail_open = rows
            .into_iter()
            .map(|(schema, table, policy)| PolicyRef {
                schema,
                table,
                policy,
            })
            .collect();

        // 6. Tenant column present, no policy on the table.
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table"
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid
            WHERE n.nspname = ANY($1)
              AND c.relkind = 'r'
              AND a.attname = $2
              AND a.attnum > 0
              AND NOT a.attisdropped
              AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            ORDER BY n.nspname, c.relname
            "#,
        )
        .bind(&schemas)
        .bind(tenant_col)
        .fetch_all(pool)
        .await?;
        report.tenant_col_no_policy = rows
            .into_iter()
            .map(|(schema, table)| TableName { schema, table })
            .collect();

        // 7. Policy USING expression doesn't mention current_setting(<guc>)
        // at all — every row visible to every tenant. Heuristic: substring
        // match on `current_setting('<guc>'`. False positives are possible
        // when a policy reads the GUC indirectly via a SQL function call
        // (the function reference won't textually contain the GUC name).
        // Documented on the field; users with such policies can filter the
        // finding out.
        let needle = format!("current_setting('{}'", self.guc_name.as_ref());
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text AS schema, c.relname::text AS "table", p.polname::text AS policy
            FROM pg_policy p
            JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY($1)
              AND COALESCE(pg_get_expr(p.polqual, p.polrelid), '') NOT ILIKE '%' || $2 || '%'
            ORDER BY n.nspname, c.relname, p.polname
            "#,
        )
        .bind(&schemas)
        .bind(&needle)
        .fetch_all(pool)
        .await?;
        report.policy_no_guc_reference = rows
            .into_iter()
            .map(|(schema, table, policy)| PolicyRef {
                schema,
                table,
                policy,
            })
            .collect();

        if report.is_clean() {
            tracing::info!(target: "pg_rls", "audit clean — no RLS misconfiguration findings");
        } else {
            tracing::warn!(
                target: "pg_rls",
                rls_no_policy = report.rls_no_policy.len(),
                policy_rls_off = report.policy_rls_off.len(),
                policy_no_force = report.policy_no_force.len(),
                policy_no_with_check = report.policy_no_with_check.len(),
                policy_fail_open = report.policy_fail_open.len(),
                tenant_col_no_policy = report.tenant_col_no_policy.len(),
                policy_no_guc_reference = report.policy_no_guc_reference.len(),
                "audit found RLS misconfigurations — fail closed at boot"
            );
        }

        Ok(report)
    }

    /// Walk a directory of `.sql` migration files and return all
    /// tenant-isolation lints. Currently `Tenancy` doesn't influence
    /// migration scanning (the scan is purely syntactic) but the method
    /// lives here for API symmetry — if a future lint depends on the
    /// configured GUC name or column, it'll fit naturally.
    pub fn scan_migrations<P: AsRef<Path>>(&self, dir: P) -> std::io::Result<Vec<Lint>> {
        scan_migrations(dir)
    }
}

/// Scan the live database for tenant-isolation invariant violations
/// using the default [`Tenancy`] (schema `public`, tenant column
/// `tenant_id`).
///
/// Equivalent to `Tenancy::default().ensure_isolation(pool).await`.
/// Use the [`Tenancy`] form to walk other schemas or recognise a
/// different tenant-column name.
pub async fn ensure_isolation(pool: &PgPool) -> sqlx::Result<Report> {
    Tenancy::default().ensure_isolation(pool).await
}

/// A single finding from [`scan_migrations`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lint {
    pub file: PathBuf,
    pub line: usize,
    pub kind: LintKind,
    /// Snippet of the offending statement, trimmed for display.
    pub snippet: String,
}

/// What [`scan_migrations`] flagged.
///
/// Marked `#[non_exhaustive]` so future variants don't break downstream
/// `match` arms — add a `_ =>` catchall in your matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LintKind {
    /// `CREATE POLICY` statement that targets a write command (or `ALL`)
    /// but has no `WITH CHECK` clause.
    PolicyMissingWithCheck,
}

impl fmt::Display for LintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LintKind::PolicyMissingWithCheck => write!(f, "CREATE POLICY without WITH CHECK"),
        }
    }
}

impl fmt::Display for Lint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {} — {}",
            self.file.display(),
            self.line,
            self.kind,
            self.snippet
        )
    }
}

/// **Lightweight syntactic lint** for `.sql` migration files. Not a
/// substitute for [`ensure_isolation`] (which queries the live schema)
/// or for review of the migration itself.
///
/// Walks the immediate children of `dir` (non-recursive, matching sqlx's
/// `migrations/` convention). For each `.sql` file, splits on `;` and
/// flags every `CREATE POLICY` statement that targets a write command
/// (`INSERT`, `UPDATE`, or the default `ALL`) and lacks an explicit
/// `WITH CHECK` clause. `FOR SELECT` and `FOR DELETE` policies don't
/// take `WITH CHECK` and are skipped.
///
/// ## Limits
///
/// - **No SQL parser.** Statement splitting is a hand-rolled pass over
///   `;` characters with line-comment stripping. Strings, dollar-quotes,
///   block comments, and other valid SQL shapes can hide statements
///   from the scanner. False negatives are possible.
/// - **Same advisory as [`Report::policy_no_with_check`]:** Postgres
///   falls back to `WITH CHECK = USING` when omitted, so the absence of
///   `WITH CHECK` is not a leak by itself. Treat findings as a
///   house-rule recommendation, not a security guarantee.
/// - **Doesn't read the live DB,** so it can't catch the FORCE / ENABLE
///   / fail-open mistakes that [`ensure_isolation`] catches.
///
/// Use it as a fast PR-time signal that complements (not replaces) the
/// boot-time audit and human review.
///
/// ```ignore
/// for lint in pg_rls::audit::scan_migrations("migrations")? {
///     eprintln!("{lint}");
/// }
/// ```
pub fn scan_migrations<P: AsRef<Path>>(dir: P) -> std::io::Result<Vec<Lint>> {
    let mut out = Vec::new();
    let dir = dir.as_ref();
    let entries = std::fs::read_dir(dir)?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let body = std::fs::read_to_string(&path)?;
        scan_sql(&path, &body, &mut out);
    }
    Ok(out)
}

fn scan_sql(file: &Path, body: &str, out: &mut Vec<Lint>) {
    let stripped = strip_sql_comments(body);
    for stmt in split_statements(&stripped) {
        let upper = stmt.text.to_ascii_uppercase();
        if !upper.contains("CREATE POLICY") {
            continue;
        }
        if upper.contains("FOR SELECT") || upper.contains("FOR DELETE") {
            continue;
        }
        if upper.contains("WITH CHECK") {
            continue;
        }
        out.push(Lint {
            file: file.to_path_buf(),
            line: stmt.line,
            kind: LintKind::PolicyMissingWithCheck,
            snippet: shorten(&collapse_ws(stmt.text)),
        });
    }
}

struct Stmt<'a> {
    text: &'a str,
    line: usize,
}

fn split_statements(body: &str) -> Vec<Stmt<'_>> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut line_at_start = 1usize;
    let mut current_line = 1usize;
    for (i, ch) in body.char_indices() {
        if start.is_none() && !ch.is_whitespace() {
            start = Some(i);
            line_at_start = current_line;
        }
        if ch == ';' {
            if let Some(s) = start {
                out.push(Stmt {
                    text: &body[s..i],
                    line: line_at_start,
                });
                start = None;
            }
        }
        if ch == '\n' {
            current_line += 1;
        }
    }
    if let Some(s) = start {
        let text = &body[s..];
        if !text.trim().is_empty() {
            out.push(Stmt {
                text,
                line: line_at_start,
            });
        }
    }
    out
}

fn strip_sql_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        if let Some(idx) = line.find("--") {
            out.push_str(&line[..idx]);
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shorten(s: &str) -> String {
    const MAX: usize = 120;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut t = s[..MAX].to_string();
        t.push_str("...");
        t
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::path::PathBuf;

    fn lint(body: &str) -> Vec<Lint> {
        let mut out = Vec::new();
        scan_sql(&PathBuf::from("test.sql"), body, &mut out);
        out
    }

    #[test]
    fn flags_missing_with_check() {
        let body =
            "CREATE POLICY p ON t USING (tenant_id = current_setting('app.tenant_id')::uuid);";
        let lints = lint(body);
        assert_eq!(lints.len(), 1);
        assert_eq!(lints[0].kind, LintKind::PolicyMissingWithCheck);
    }

    #[test]
    fn passes_with_check_present() {
        let body = "CREATE POLICY p ON t \
                    USING (tenant_id = current_setting('app.tenant_id')::uuid) \
                    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);";
        assert!(lint(body).is_empty());
    }

    #[test]
    fn skips_for_select() {
        let body = "CREATE POLICY p ON t FOR SELECT \
                    USING (tenant_id = current_setting('app.tenant_id')::uuid);";
        assert!(lint(body).is_empty());
    }

    #[test]
    fn skips_for_delete() {
        let body = "CREATE POLICY p ON t FOR DELETE \
                    USING (tenant_id = current_setting('app.tenant_id')::uuid);";
        assert!(lint(body).is_empty());
    }

    #[test]
    fn ignores_create_policy_in_line_comment() {
        let body = "-- CREATE POLICY p ON t USING (true);\nSELECT 1;";
        assert!(lint(body).is_empty());
    }

    #[test]
    fn reports_line_number_of_statement_start() {
        let body = "SELECT 1;\n\nCREATE POLICY p ON t \n  USING (true);\n";
        let lints = lint(body);
        assert_eq!(lints.len(), 1);
        assert_eq!(lints[0].line, 3);
    }

    #[test]
    fn flags_each_offender_in_a_multi_statement_file() {
        let body = "\
            CREATE POLICY a ON t USING (true);\n\
            CREATE POLICY b ON t USING (true) WITH CHECK (true);\n\
            CREATE POLICY c ON u USING (true);\n\
        ";
        let lints = lint(body);
        assert_eq!(lints.len(), 2);
        assert!(lints[0].snippet.contains(" a "));
        assert!(lints[1].snippet.contains(" c "));
    }

    #[test]
    fn quoted_semicolon_causes_a_false_positive() {
        let body = "\
            CREATE POLICY p ON t \
            USING ('value;still a string' = tenant_id::text) \
            WITH CHECK ('value;still a string' = tenant_id::text);\
        ";
        let lints = lint(body);
        assert_eq!(lints.len(), 1);
        assert_eq!(lints[0].kind, LintKind::PolicyMissingWithCheck);
    }

    #[test]
    fn double_dash_inside_string_causes_a_false_positive() {
        let body = "\
            CREATE POLICY p ON t \
            USING ('value -- not a comment' = tenant_id::text) \
            WITH CHECK ('value -- not a comment' = tenant_id::text);\
        ";
        let lints = lint(body);
        assert_eq!(lints.len(), 1);
        assert_eq!(lints[0].kind, LintKind::PolicyMissingWithCheck);
    }
}
