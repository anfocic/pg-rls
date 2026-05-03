//! Integration tests for `audit::ensure_isolation` against a live Postgres.
//!
//! Each test creates uniquely-named tables (suffixed with a random UUID) so
//! parallel test runs don't collide. After exercising the audit, the table
//! is dropped — but if a test panics mid-run, leftover tables are still
//! flagged by future runs of the audit; tests therefore filter the report
//! down to their own table names before asserting.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use pg_rls::audit::{self, Report};
use pg_rls::Tenancy;
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string())
}

async fn pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url())
        .await
        .expect("connect")
}

fn unique_suffix() -> String {
    Uuid::new_v4().simple().to_string()
}

async fn drop_table(pool: &PgPool, table: &str) {
    let sql = format!("DROP TABLE IF EXISTS {table} CASCADE");
    sqlx::query(&sql).execute(pool).await.expect("drop table");
}

fn rls_no_policy_for(report: &Report, table: &str) -> bool {
    report.rls_no_policy.iter().any(|t| t.table == table)
}

fn missing_with_check_for(report: &Report, table: &str, policy: &str) -> bool {
    report
        .policy_no_with_check
        .iter()
        .any(|p| p.table == table && p.policy == policy)
}

fn fail_open_for(report: &Report, table: &str, policy: &str) -> bool {
    report
        .policy_fail_open
        .iter()
        .any(|p| p.table == table && p.policy == policy)
}

fn tenant_col_no_policy_for(report: &Report, table: &str) -> bool {
    report.tenant_col_no_policy.iter().any(|t| t.table == table)
}

fn policy_rls_off_for(report: &Report, table: &str) -> bool {
    report.policy_rls_off.iter().any(|t| t.table == table)
}

fn policy_no_force_for(report: &Report, table: &str) -> bool {
    report.policy_no_force.iter().any(|t| t.table == table)
}

fn policy_no_guc_reference_for(report: &Report, table: &str, policy: &str) -> bool {
    report
        .policy_no_guc_reference
        .iter()
        .any(|p| p.table == table && p.policy == policy)
}

/// A policy whose USING expression doesn't reference
/// `current_setting('<guc>'` at all is flagged. `USING (TRUE)` is the
/// most permissive possible policy — every tenant sees every row.
#[tokio::test]
async fn flags_policy_without_guc_reference() {
    let pool = pool().await;
    let table = format!("audit_no_guc_ref_{}", unique_suffix());
    let policy = "permissive";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} USING (TRUE) WITH CHECK (TRUE)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        policy_no_guc_reference_for(&report, &table, policy),
        "expected `{table}::{policy}` in policy_no_guc_reference:\n{report}"
    );
}

/// A policy that references the configured GUC (even via a mismatched
/// column type) is NOT flagged in `policy_no_guc_reference`. Negative
/// case for the heuristic.
#[tokio::test]
async fn does_not_flag_policy_referencing_guc() {
    let pool = pool().await;
    let table = format!("audit_with_guc_ref_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid) \
         WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        !policy_no_guc_reference_for(&report, &table, policy),
        "policy that references current_setting should not be flagged:\n{report}"
    );
}

#[tokio::test]
async fn flags_table_with_rls_enabled_but_no_policy() {
    let pool = pool().await;
    let table = format!("audit_rls_no_policy_{}", unique_suffix());

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, body TEXT)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        rls_no_policy_for(&report, &table),
        "expected `{table}` in rls_no_policy:\n{report}"
    );
}

#[tokio::test]
async fn flags_policy_missing_with_check_on_all_command() {
    let pool = pool().await;
    let table = format!("audit_no_with_check_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        missing_with_check_for(&report, &table, policy),
        "expected `{table}::{policy}` in policy_no_with_check:\n{report}"
    );
}

#[tokio::test]
async fn does_not_flag_for_select_only_policy() {
    let pool = pool().await;
    let table = format!("audit_for_select_{}", unique_suffix());
    let policy = "select_only";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} FOR SELECT \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        !missing_with_check_for(&report, &table, policy),
        "FOR SELECT policy should not be flagged as missing WITH CHECK:\n{report}"
    );
}

#[tokio::test]
async fn flags_fail_open_coalesce_pattern() {
    let pool = pool().await;
    let table = format!("audit_fail_open_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), tenant_id::text)::uuid) \
         WITH CHECK (tenant_id = COALESCE(current_setting('app.tenant_id', true), tenant_id::text)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        fail_open_for(&report, &table, policy),
        "expected `{table}::{policy}` in policy_fail_open:\n{report}"
    );
}

#[tokio::test]
async fn flags_tenant_id_column_with_no_policy() {
    let pool = pool().await;
    let table = format!("audit_tenant_no_policy_{}", unique_suffix());

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, body TEXT)"
    ))
    .execute(&pool)
    .await
    .expect("create table");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        tenant_col_no_policy_for(&report, &table),
        "expected `{table}` in tenant_col_no_policy:\n{report}"
    );
}

/// Custom tenant-column name (e.g. `org_id`) is honored: a table with
/// that column but no policy is flagged, while a table with the default
/// `tenant_id` column is not.
#[tokio::test]
async fn custom_tenant_column_is_honored() {
    let pool = pool().await;
    let table_org = format!("audit_custom_org_{}", unique_suffix());
    let table_default = format!("audit_custom_default_{}", unique_suffix());

    sqlx::query(&format!(
        "CREATE TABLE {table_org} (id UUID PRIMARY KEY, org_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create org table");
    sqlx::query(&format!(
        "CREATE TABLE {table_default} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create default table");

    let report = Tenancy::new()
        .tenant_column("org_id")
        .ensure_isolation(&pool)
        .await
        .expect("audit");

    drop_table(&pool, &table_org).await;
    drop_table(&pool, &table_default).await;

    assert!(
        tenant_col_no_policy_for(&report, &table_org),
        "expected org-column table `{table_org}` in tenant_col_no_policy:\n{report}"
    );
    assert!(
        !tenant_col_no_policy_for(&report, &table_default),
        "default-column table `{table_default}` should not be flagged when audit \
         is configured for `org_id`:\n{report}"
    );
}

/// A table with a policy attached but RLS not enabled is flagged —
/// Postgres silently ignores the policy in this state.
#[tokio::test]
async fn flags_policy_with_rls_disabled() {
    let pool = pool().await;
    let table = format!("audit_rls_off_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    // Note: NO `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY`.
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        policy_rls_off_for(&report, &table),
        "expected `{table}` in policy_rls_off:\n{report}"
    );
}

/// A table with policy + ENABLE but no FORCE is flagged — owner role
/// bypasses non-FORCE policies, which is the most common multi-tenant
/// leak in production.
#[tokio::test]
async fn flags_policy_without_force() {
    let pool = pool().await;
    let table = format!("audit_no_force_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    // Note: NO `FORCE ROW LEVEL SECURITY`.
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid) \
         WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        policy_no_force_for(&report, &table),
        "expected `{table}` in policy_no_force:\n{report}"
    );
}

/// `Tenancy::policy_template(...).full_sql()` produces SQL that
/// `ensure_isolation` accepts as clean. Locks the contract that the
/// helpers and the audit speak the same canonical shape.
#[tokio::test]
async fn policy_template_round_trip_is_audit_clean() {
    let pool = pool().await;
    let table = format!("policy_round_trip_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, body TEXT)"
    ))
    .execute(&pool)
    .await
    .expect("create table");

    let tenancy = Tenancy::default();
    let template = tenancy
        .policy_template(table.clone())
        .policy_name(policy)
        .cast("uuid");

    for stmt in [
        template.enable_rls_sql(),
        template.force_rls_sql(),
        template.create_policy_sql(),
    ] {
        sqlx::query(&stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to apply helper SQL `{stmt}`: {e}"));
    }

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        !rls_no_policy_for(&report, &table),
        "helper output should not appear in rls_no_policy:\n{report}"
    );
    assert!(
        !policy_rls_off_for(&report, &table),
        "helper output should not appear in policy_rls_off:\n{report}"
    );
    assert!(
        !policy_no_force_for(&report, &table),
        "helper output should not appear in policy_no_force:\n{report}"
    );
    assert!(
        !missing_with_check_for(&report, &table, policy),
        "helper output should not appear in policy_no_with_check:\n{report}"
    );
    assert!(
        !fail_open_for(&report, &table, policy),
        "helper output should not appear in policy_fail_open:\n{report}"
    );
    assert!(
        !tenant_col_no_policy_for(&report, &table),
        "helper output should not appear in tenant_col_no_policy:\n{report}"
    );
}

#[tokio::test]
async fn passes_clean_tenant_table() {
    let pool = pool().await;
    let table = format!("audit_clean_{}", unique_suffix());
    let policy = "tenant_iso";

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, body TEXT)"
    ))
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force rls");
    sqlx::query(&format!(
        "CREATE POLICY {policy} ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid) \
         WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    assert!(
        !rls_no_policy_for(&report, &table),
        "clean table should not appear in rls_no_policy:\n{report}"
    );
    assert!(
        !policy_rls_off_for(&report, &table),
        "clean table should not appear in policy_rls_off:\n{report}"
    );
    assert!(
        !policy_no_force_for(&report, &table),
        "FORCE-applied table should not appear in policy_no_force:\n{report}"
    );
    assert!(
        !missing_with_check_for(&report, &table, policy),
        "clean policy should not appear in policy_no_with_check:\n{report}"
    );
    assert!(
        !fail_open_for(&report, &table, policy),
        "clean policy should not appear in policy_fail_open:\n{report}"
    );
    assert!(
        !tenant_col_no_policy_for(&report, &table),
        "tenant table with policy should not appear in tenant_col_no_policy:\n{report}"
    );
    assert!(
        !policy_no_guc_reference_for(&report, &table, policy),
        "clean policy referencing current_setting should not appear in policy_no_guc_reference:\n{report}"
    );
}
