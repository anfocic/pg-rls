//! Integration tests for the pool-hook layer.
//!
//! Regression target: sqlx 0.8's `before_acquire` does not fire for
//! freshly-opened connections — only for connections already in the
//! pool's idle list. A `before_acquire`-only design leaves `app.tenant_id`
//! unset on the first query against a new connection — invisible under
//! fail-open `COALESCE` RLS, but `unrecognized configuration parameter`
//! under fail-closed RLS. `pg-rls` mirrors the SET into `after_connect`
//! to cover this; this test asserts the mirror is in place.

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::time::Duration;
use pg_rls::pool::{self, TENANT_ID};
use pg_rls::{Tenancy, TenantId};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string())
}

#[tokio::test]
async fn fresh_connection_has_tenant_guc_set() {
    let pool = pool::with_tenant_hooks(
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5)),
    )
    .connect(&db_url())
    .await
    .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    // current_setting('app.tenant_id', false) raises if the GUC is unknown
    // to this session, so this query is the right pass/fail signal: a
    // fresh checkout under TENANT_ID::scope must already have it set.
    let observed: String = TENANT_ID
        .scope(tenant, async {
            let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
                .fetch_one(&pool)
                .await
                .expect("select current_setting");
            row.get::<String, _>("v")
        })
        .await;

    assert_eq!(observed, expected);
}

#[tokio::test]
async fn user_after_connect_can_compose_via_helper() {
    let pool = pool::with_tenant_hooks(
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5)),
    )
    .after_connect(|conn, _meta| {
        Box::pin(async move {
            sqlx::query("SET statement_timeout = '5s'")
                .execute(&mut *conn)
                .await?;
            pool::tenant_after_connect_hook(conn).await?;
            Ok(())
        })
    })
    .connect(&db_url())
    .await
    .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let observed: String = TENANT_ID
        .scope(tenant, async {
            let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
                .fetch_one(&pool)
                .await
                .expect("select current_setting");
            row.get::<String, _>("v")
        })
        .await;

    assert_eq!(observed, expected);
}

#[tokio::test]
async fn test_pool_options_preserves_tenant_guc() {
    let pool = pool::test_pool_options()
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url())
        .await
        .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let observed: String = TENANT_ID
        .scope(tenant, async {
            let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
                .fetch_one(&pool)
                .await
                .expect("select current_setting");
            row.get::<String, _>("v")
        })
        .await;

    assert_eq!(observed, expected);
}

/// Custom GUC name configured via `Tenancy` is honored end-to-end —
/// pool hooks SET into the configured GUC, and reading it back
/// confirms the value.
#[tokio::test]
async fn custom_guc_name_is_honored_by_pool_hooks() {
    let tenancy = Tenancy::new().guc("app.org_id");
    let pool = tenancy
        .with_tenant_hooks(
            PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(5)),
        )
        .connect(&db_url())
        .await
        .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let observed: String = TENANT_ID
        .scope(tenant, async {
            let row = sqlx::query("SELECT current_setting('app.org_id', false) AS v")
                .fetch_one(&pool)
                .await
                .expect("select current_setting");
            row.get::<String, _>("v")
        })
        .await;

    assert_eq!(observed, expected);
}

/// String tenant IDs (e.g. slugs) work end-to-end. Demonstrates the
/// generic `TenantId(String)` path: a tenant whose ID is "acme-co" is
/// stored verbatim in the GUC.
#[tokio::test]
async fn string_tenant_id_is_honored() {
    let pool = pool::with_tenant_hooks(
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5)),
    )
    .connect(&db_url())
    .await
    .expect("connect");

    let tenant = TenantId::new("acme-co");

    let observed: String = TENANT_ID
        .scope(tenant, async {
            let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
                .fetch_one(&pool)
                .await
                .expect("select current_setting");
            row.get::<String, _>("v")
        })
        .await;

    assert_eq!(observed, "acme-co");
}
