//! [`Tenancy`] — the configuration object that every other module reads
//! from. Knobs:
//!
//! - **`guc_name`** (default `"app.tenant_id"`) — the Postgres
//!   `current_setting` key that pool hooks `set_config` into and that
//!   your RLS policies read from.
//! - **`schemas`** (default `["public"]`) — schemas the audit walks. Add
//!   more if your tenant tables live elsewhere.
//! - **`tenant_column`** (default `"tenant_id"`) — column name the audit
//!   recognises as a tenant tag when checking for tables that are tagged
//!   but unprotected by a policy.
//!
//! All three identifiers are validated at construction time (PG identifier
//! rules: ASCII alphanumerics and underscores, must start with a letter or
//! underscore, ≤ 63 chars per part). Validation panics — these are
//! developer-set constants, not user input, and a bad config is a bug at
//! deploy time, not a runtime concern.
//!
//! ## What each knob affects
//!
//! - **`guc(...)`** changes the Postgres setting name used by pool hooks,
//!   [`crate::set_tenant`], [`crate::PgPoolExt::begin_tenant`], and the
//!   policy SQL you write in your migrations.
//! - **`schema(...)` / `schemas(...)`** only change the scope that the
//!   live audit walks. They do not alter runtime query scoping.
//! - **`tenant_column(...)`** only changes the audit heuristic that looks
//!   for tables that appear tenant-tagged but have no policy. It does not
//!   affect pool hooks or transaction-scoped tenant binding.
//!
//! ## Example
//!
//! ```no_run
//! # async fn run() -> sqlx::Result<()> {
//! use sqlx::postgres::PgPoolOptions;
//! use pg_rls::Tenancy;
//!
//! // Default: app.tenant_id, public schema, tenant_id column.
//! let pool = Tenancy::default()
//!     .with_tenant_hooks(PgPoolOptions::new().max_connections(8))
//!     .connect("postgres://...").await?;
//! # let _ = pool;
//!
//! // Custom: org_id GUC, app schema, org_id column.
//! let custom = Tenancy::new()
//!     .guc("app.org_id")
//!     .schema("app")
//!     .tenant_column("org_id");
//! let pool = custom
//!     .with_tenant_hooks(PgPoolOptions::new())
//!     .connect("postgres://...").await?;
//! # let _ = pool;
//! # Ok(()) }
//! ```

use std::borrow::Cow;

/// Run-time tenancy configuration. Default values are the conventional
/// shape: `app.tenant_id` GUC, `public` schema, `tenant_id` column.
///
/// Build with [`Tenancy::default`] for the conventional shape, or
/// [`Tenancy::new`] + builder methods for a custom fit. Cheap to clone;
/// the pool hooks clone it into closures so each `with_tenant_hooks` call
/// produces an independently-configured pool.
#[derive(Debug, Clone)]
pub struct Tenancy {
    pub(crate) guc_name: Cow<'static, str>,
    pub(crate) schemas: Vec<Cow<'static, str>>,
    pub(crate) tenant_column: Cow<'static, str>,
}

impl Default for Tenancy {
    fn default() -> Self {
        Self {
            guc_name: Cow::Borrowed("app.tenant_id"),
            schemas: vec![Cow::Borrowed("public")],
            tenant_column: Cow::Borrowed("tenant_id"),
        }
    }
}

impl Tenancy {
    /// Equivalent to [`Tenancy::default`]. Provided for builder-chaining
    /// readability: `Tenancy::new().guc("app.org_id")`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the Postgres GUC name (default `"app.tenant_id"`).
    ///
    /// Two-part identifier required: `<class>.<key>`, e.g. `app.org_id`.
    /// This affects both runtime tenant binding and the policy SQL you
    /// write against `current_setting(...)`. Panics if the value isn't a
    /// valid PG custom GUC identifier.
    pub fn guc(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let name = name.into();
        validate_guc(&name);
        self.guc_name = name;
        self
    }

    /// Replace the schema list with a single schema (default `"public"`).
    ///
    /// This affects only the live audit's search scope; it does not
    /// change runtime query scoping.
    ///
    /// Panics if the value isn't a valid PG identifier.
    pub fn schema(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let name = name.into();
        validate_identifier(&name);
        self.schemas = vec![name];
        self
    }

    /// Replace the schema list with multiple schemas.
    ///
    /// Use when tenant-scoped tables live across more than one schema.
    /// This affects only the live audit's search scope; it does not
    /// change runtime query scoping.
    ///
    /// Panics if any value isn't a valid PG identifier; panics if the
    /// iterator is empty.
    pub fn schemas<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Cow<'static, str>>,
    {
        let names: Vec<Cow<'static, str>> = names.into_iter().map(Into::into).collect();
        assert!(
            !names.is_empty(),
            "pg-rls: Tenancy::schemas needs at least one schema"
        );
        for n in &names {
            validate_identifier(n);
        }
        self.schemas = names;
        self
    }

    /// Override the column name the audit recognises as a tenant tag
    /// (default `"tenant_id"`).
    ///
    /// This affects only the audit heuristic for "tenant column but no
    /// policy attached". Runtime tenant binding still uses the configured
    /// GUC and your own policy SQL.
    ///
    /// Panics if the value isn't a valid PG identifier.
    pub fn tenant_column(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let name = name.into();
        validate_identifier(&name);
        self.tenant_column = name;
        self
    }

    /// Start a [`PolicyTemplate`](crate::PolicyTemplate) for `table`,
    /// preconfigured with this `Tenancy`'s GUC name and tenant column.
    /// The schema defaults to the first entry of [`schemas`](Self::schemas);
    /// the policy name defaults to `tenant_isolation`. Both are
    /// overridable on the returned template.
    ///
    /// Panics if `table` isn't a valid PG identifier.
    ///
    /// ```
    /// use pg_rls::Tenancy;
    ///
    /// let sql = Tenancy::default()
    ///     .policy_template("orders")
    ///     .cast("uuid")
    ///     .full_sql();
    /// assert!(sql.contains("CREATE POLICY \"tenant_isolation\""));
    /// ```
    pub fn policy_template(
        &self,
        table: impl Into<Cow<'static, str>>,
    ) -> crate::policy::PolicyTemplate<'_> {
        crate::policy::PolicyTemplate::new(self, table)
    }

    /// Borrow the configured GUC name. Useful for diagnostics.
    pub fn guc_name(&self) -> &str {
        &self.guc_name
    }

    /// Borrow the configured schema list.
    pub fn schemas_slice(&self) -> Vec<&str> {
        self.schemas.iter().map(|s| s.as_ref()).collect()
    }

    /// Borrow the configured tenant-column name.
    pub fn tenant_column_name(&self) -> &str {
        &self.tenant_column
    }
}

/// Validate a single PG identifier (schema name, column name, GUC class
/// or key). Rules:
///
/// - non-empty, ≤ 63 ASCII chars (PG's `NAMEDATALEN - 1` limit)
/// - first char ASCII letter or `_`
/// - subsequent chars ASCII alphanumerics or `_`
///
/// Panics with a descriptive message on any violation. Constants set by
/// the integrator should always be valid; a panic means the integrator
/// passed something that would either fail at the SQL boundary or risk
/// injection if formatted into a query.
pub(crate) fn validate_identifier(s: &str) {
    assert!(!s.is_empty(), "pg-rls: identifier is empty");
    assert!(
        s.len() <= 63,
        "pg-rls: identifier `{s}` exceeds 63 chars (Postgres NAMEDATALEN)"
    );
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    assert!(
        first.is_ascii_alphabetic() || first == '_',
        "pg-rls: identifier `{s}` must start with an ASCII letter or `_`"
    );
    for c in chars {
        assert!(
            c.is_ascii_alphanumeric() || c == '_',
            "pg-rls: identifier `{s}` contains invalid char `{c}` \
             (only ASCII alphanumerics and `_` allowed)"
        );
    }
}

/// Validate a PG custom GUC name: exactly two dot-separated PG
/// identifiers (`<class>.<key>`).
pub(crate) fn validate_guc(s: &str) {
    assert!(!s.is_empty(), "pg-rls: GUC name is empty");
    let parts: Vec<&str> = s.split('.').collect();
    assert!(
        parts.len() == 2,
        "pg-rls: GUC name `{s}` must be exactly two identifiers \
         (`<class>.<key>`)"
    );
    for part in parts {
        validate_identifier(part);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let t = Tenancy::default();
        assert_eq!(t.guc_name(), "app.tenant_id");
        assert_eq!(t.schemas_slice(), vec!["public"]);
        assert_eq!(t.tenant_column_name(), "tenant_id");
    }

    #[test]
    fn builder_overrides() {
        let t = Tenancy::new()
            .guc("app.org_id")
            .schema("app")
            .tenant_column("org_id");
        assert_eq!(t.guc_name(), "app.org_id");
        assert_eq!(t.schemas_slice(), vec!["app"]);
        assert_eq!(t.tenant_column_name(), "org_id");
    }

    #[test]
    fn schemas_multi() {
        let t = Tenancy::new().schemas(["app", "data"]);
        assert_eq!(t.schemas_slice(), vec!["app", "data"]);
    }

    #[test]
    #[should_panic(expected = "must be exactly two identifiers")]
    fn rejects_dash_in_guc() {
        let _ = Tenancy::new().guc("bad-guc");
    }

    #[test]
    #[should_panic(expected = "must be exactly two identifiers")]
    fn rejects_three_part_guc() {
        let _ = Tenancy::new().guc("a.b.c");
    }

    #[test]
    #[should_panic(expected = "must be exactly two identifiers")]
    fn rejects_single_part_guc() {
        let _ = Tenancy::new().guc("tenant_id");
    }

    #[test]
    #[should_panic(expected = "identifier `1abc`")]
    fn rejects_leading_digit() {
        let _ = Tenancy::new().schema("1abc");
    }

    #[test]
    #[should_panic(expected = "needs at least one schema")]
    fn rejects_empty_schemas() {
        let _ = Tenancy::new().schemas::<[&str; 0], _>([]);
    }

    #[test]
    fn accepts_underscores_and_digits() {
        let t = Tenancy::new()
            .guc("app2.tenant_id_v2")
            .schema("app_v2")
            .tenant_column("tenant_id_2");
        assert_eq!(t.guc_name(), "app2.tenant_id_v2");
    }
}
