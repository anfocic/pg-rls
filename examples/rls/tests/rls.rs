//! Proof tests for the RLS pattern.
//!
//! `naive_leaks_cross_tenant_reads` shows the bug — RLS without FORCE is
//! bypassed by the table owner, so tenant B reads tenant A's row.
//!
//! `fixed_blocks_cross_tenant_reads` and `fixed_with_check_blocks_cross_tenant_writes`
//! show the fix — same setup, but on the table that has `FORCE ROW LEVEL SECURITY`
//! and `WITH CHECK`, the cross-tenant read is empty and the cross-tenant write is rejected.

use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::Path;
use std::time::Duration;
use pg_rls::{set_tenant, TenantId};
use pg_rls_example::{insert_fixed, insert_naive, list_fixed, list_naive};
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect");
    Migrator::new(Path::new("./migrations"))
        .await
        .expect("load migrations")
        .run(&pool)
        .await
        .expect("migrate");
    pool
}

#[tokio::test]
async fn naive_leaks_cross_tenant_reads() {
    let pool = pool().await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    insert_naive(&pool, tenant_a, "tenant a's secret")
        .await
        .expect("insert as tenant a");

    let visible_to_b = list_naive(&pool, tenant_b).await.expect("list as tenant b");

    let leaked: Vec<_> = visible_to_b
        .into_iter()
        .filter(|n| n.tenant_id == tenant_a)
        .collect();

    assert_eq!(
        leaked.len(),
        1,
        "BUG: tenant B should not see tenant A's row, \
         but RLS without FORCE is bypassed by the owner role"
    );
    assert_eq!(leaked[0].body, "tenant a's secret");
}

#[tokio::test]
async fn fixed_blocks_cross_tenant_reads() {
    let pool = pool().await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    insert_fixed(&pool, tenant_a, "tenant a's secret")
        .await
        .expect("insert as tenant a");

    let visible_to_b = list_fixed(&pool, tenant_b).await.expect("list as tenant b");

    let leaked: Vec<_> = visible_to_b
        .into_iter()
        .filter(|n| n.tenant_id == tenant_a)
        .collect();

    assert!(
        leaked.is_empty(),
        "FORCE ROW LEVEL SECURITY should block cross-tenant reads, got {} leaked",
        leaked.len()
    );
}

#[tokio::test]
async fn fixed_with_check_blocks_cross_tenant_writes() {
    let pool = pool().await;
    let tenant_a = TenantId::from(Uuid::new_v4());
    let tenant_b_uuid = Uuid::new_v4();

    let mut tx = pool.begin().await.expect("begin");
    set_tenant(&mut tx, &tenant_a).await.expect("set tenant a");

    let result = sqlx::query("INSERT INTO fixed_notes (tenant_id, body) VALUES ($1, $2)")
        .bind(tenant_b_uuid)
        .bind("forged write")
        .execute(&mut *tx)
        .await;

    assert!(
        result.is_err(),
        "WITH CHECK should reject inserting a row tagged with another tenant's id"
    );
}
