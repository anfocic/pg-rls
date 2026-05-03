//! Canonical RLS policy SQL emitter.
//!
//! Hand-written `CREATE POLICY` statements are where most of the gotchas
//! in this crate's README appear: missing `FORCE`, missing `WITH CHECK`,
//! wrong GUC name, accidental fail-open with `COALESCE`.
//! [`PolicyTemplate`] emits the canonical shape sourced from a [`Tenancy`]
//! so the policy text reads the configured GUC and is accepted by
//! [`audit::ensure_isolation`](crate::audit::ensure_isolation) as clean.
//!
//! Construct via [`Tenancy::policy_template`].
//!
//! ```
//! use pg_rls::Tenancy;
//!
//! let sql = Tenancy::default()
//!     .policy_template("orders")
//!     .cast("uuid")
//!     .full_sql();
//! assert!(sql.contains("FORCE ROW LEVEL SECURITY"));
//! assert!(sql.contains("WITH CHECK"));
//! ```

use std::borrow::Cow;
use std::fmt::Write;

use crate::config::validate_identifier;
use crate::Tenancy;

/// Builder for the three SQL statements that make a tenant-scoped table
/// audit-clean: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`,
/// `ALTER TABLE ... FORCE ROW LEVEL SECURITY`, and
/// `CREATE POLICY ... USING (...) WITH CHECK (...)`.
///
/// All identifiers are validated at builder time (same rules as
/// [`Tenancy`]'s own builder methods); invalid input panics.
pub struct PolicyTemplate<'a> {
    tenancy: &'a Tenancy,
    schema: Cow<'static, str>,
    table: Cow<'static, str>,
    policy_name: Cow<'static, str>,
    cast: Option<Cow<'static, str>>,
}

impl<'a> PolicyTemplate<'a> {
    pub(crate) fn new(tenancy: &'a Tenancy, table: impl Into<Cow<'static, str>>) -> Self {
        let table = table.into();
        validate_identifier(&table);
        Self {
            schema: tenancy.schemas[0].clone(),
            tenancy,
            table,
            policy_name: Cow::Borrowed("tenant_isolation"),
            cast: None,
        }
    }

    /// Override the schema. Defaults to the first entry of the
    /// [`Tenancy`]'s schema list (`public` for the default config).
    pub fn schema(mut self, schema: impl Into<Cow<'static, str>>) -> Self {
        let s = schema.into();
        validate_identifier(&s);
        self.schema = s;
        self
    }

    /// Override the policy name. Defaults to `"tenant_isolation"`.
    pub fn policy_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let n = name.into();
        validate_identifier(&n);
        self.policy_name = n;
        self
    }

    /// Cast `current_setting(...)` to a Postgres type before comparing
    /// (e.g. `"uuid"` for a `uuid` tenant column, `"bigint"` for `int8`).
    /// Without a cast, the predicate compares the column to a `text`
    /// value — which is correct for `text` tenant columns and a SQL type
    /// error for anything else.
    pub fn cast(mut self, ty: impl Into<Cow<'static, str>>) -> Self {
        let ty = ty.into();
        validate_identifier(&ty);
        self.cast = Some(ty);
        self
    }

    /// `ALTER TABLE "<schema>"."<table>" ENABLE ROW LEVEL SECURITY;`
    pub fn enable_rls_sql(&self) -> String {
        format!(
            "ALTER TABLE {} ENABLE ROW LEVEL SECURITY;",
            self.qualified_table()
        )
    }

    /// `ALTER TABLE "<schema>"."<table>" FORCE ROW LEVEL SECURITY;`
    pub fn force_rls_sql(&self) -> String {
        format!(
            "ALTER TABLE {} FORCE ROW LEVEL SECURITY;",
            self.qualified_table()
        )
    }

    /// `CREATE POLICY ... USING (...) WITH CHECK (...);`
    ///
    /// The USING expression is mirrored into the WITH CHECK clause so
    /// writes are gated by the same predicate as reads — satisfying the
    /// audit's `policy_no_with_check` recommendation.
    pub fn create_policy_sql(&self) -> String {
        let predicate = self.predicate();
        format!(
            "CREATE POLICY \"{policy}\" ON {table}\n  \
             USING ({predicate})\n  \
             WITH CHECK ({predicate});",
            policy = self.policy_name,
            table = self.qualified_table(),
        )
    }

    /// All three statements concatenated, each terminated with `;` and
    /// followed by a newline. Suitable for piping into `sqlx::query` per
    /// statement (split on `";\n"`) or pasting into a migration file.
    pub fn full_sql(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{}", self.enable_rls_sql());
        let _ = writeln!(out, "{}", self.force_rls_sql());
        let _ = writeln!(out, "{}", self.create_policy_sql());
        out
    }

    fn qualified_table(&self) -> String {
        format!("\"{}\".\"{}\"", self.schema, self.table)
    }

    fn predicate(&self) -> String {
        let column = self.tenancy.tenant_column.as_ref();
        let guc = self.tenancy.guc_name.as_ref();
        match &self.cast {
            None => format!("\"{column}\" = current_setting('{guc}', true)"),
            Some(ty) => format!("\"{column}\" = current_setting('{guc}', true)::{ty}"),
        }
    }
}
