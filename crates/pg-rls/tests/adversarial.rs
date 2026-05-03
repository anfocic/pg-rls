//! Adversarial integration tests. Each one is an attempt to break the
//! crate's promises — leak across tenants, smuggle SQL through tenant
//! values, or bypass the binding via concurrency. All of them MUST pass
//! (i.e. demonstrate the crate doesn't break) for the public claims to
//! hold.

#![cfg(feature = "axum")]

use pg_rls::{pool, PgPoolExt, TenantId};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string())
}

async fn fresh_pool() -> PgPool {
    pool::with_tenant_hooks(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5)),
    )
    .connect(&db_url())
    .await
    .expect("connect")
}

async fn drop_table(pool: &PgPool, table: &str) {
    let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table} CASCADE"))
        .execute(pool)
        .await;
}

/// A canonical tenant-scoped table with FORCE + WITH CHECK + non-superuser role.
async fn create_isolated_table(pool: &PgPool, table: &str) {
    sqlx::query(&format!(
        "CREATE TABLE {table} (\
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), \
            tenant_id UUID NOT NULL, \
            body TEXT NOT NULL\
        )"
    ))
    .execute(pool)
    .await
    .expect("create");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(pool)
        .await
        .expect("enable");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(pool)
        .await
        .expect("force");
    sqlx::query(&format!(
        "CREATE POLICY tenant_iso ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid) \
         WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(pool)
    .await
    .expect("policy");
}

fn unique(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().simple())
}

/// Attack 1: TenantId value contains SQL-injection-flavoured content.
/// Expectation: value is bound as a parameter to set_config, never
/// interpolated into a query string. Should be inert.
#[tokio::test]
async fn tenant_id_with_injection_payload_is_inert() {
    let pool = fresh_pool().await;
    let table = unique("adv_inject");
    create_isolated_table(&pool, &table).await;

    let real_tenant = Uuid::new_v4();
    let evil = TenantId::from(format!("'; DROP TABLE {table}; --"));

    // Insert one row legitimately under the real tenant.
    {
        let bind = TenantId::from(real_tenant);
        let mut tx = pool.begin_tenant(&bind).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO {table} (tenant_id, body) VALUES ($1, 'real')"
        ))
        .bind(real_tenant)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // Try to use the malicious tenant value. It should bind cleanly and
    // RLS should treat it as a different (non-matching) tenant. The
    // table must still exist after.
    let result = pool.begin_tenant(&evil).await;
    if let Ok(mut tx) = result {
        let _ = sqlx::query(&format!("SELECT body FROM {table}"))
            .fetch_all(&mut *tx)
            .await; // either empty result or type-cast error; either is fine
        let _ = tx.rollback().await;
    }

    // Table must still exist.
    let still_there: (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)")
            .bind(&table)
            .fetch_one(&pool)
            .await
            .expect("query");
    assert!(still_there.0, "evil TenantId dropped the table — injection leak");

    drop_table(&pool, &table).await;
}

/// Attack 2: Empty TenantId. Sets the GUC to empty string.
/// Expectation: query against a uuid-cast policy fails cleanly with a
/// type error (NOT a silent leak / NOT a panic). Empty-string is a
/// developer footgun but must fail closed.
#[tokio::test]
async fn empty_tenant_id_fails_closed() {
    let pool = fresh_pool().await;
    let table = unique("adv_empty");
    create_isolated_table(&pool, &table).await;

    let real = Uuid::new_v4();
    {
        let bind = TenantId::from(real);
        let mut tx = pool.begin_tenant(&bind).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO {table} (tenant_id, body) VALUES ($1, 'real')"
        ))
        .bind(real)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let empty = TenantId::new("");
    let mut tx = pool.begin_tenant(&empty).await.unwrap();
    let result: Result<Vec<(String,)>, _> = sqlx::query_as(&format!("SELECT body FROM {table}"))
        .fetch_all(&mut *tx)
        .await;

    match result {
        Ok(rows) => {
            assert!(
                rows.is_empty(),
                "empty TenantId returned {} rows — SILENT LEAK",
                rows.len()
            );
        }
        Err(e) => {
            // Acceptable: type error from uuid cast of "". Fails closed.
            let msg = e.to_string();
            assert!(
                msg.contains("invalid input") || msg.contains("uuid"),
                "expected uuid cast error, got: {msg}"
            );
        }
    }

    let _ = tx.rollback().await;
    drop_table(&pool, &table).await;
}

/// Attack 3: Plain `tokio::spawn` (no `spawn_with_tenant`) tries to read
/// the parent's tenant data. README says this loses the binding.
/// Expectation: the spawned task sees no rows (RLS fails closed).
#[tokio::test]
async fn plain_spawn_does_not_inherit_tenant_binding() {
    let pool = fresh_pool().await;
    let table = unique("adv_spawn");
    create_isolated_table(&pool, &table).await;

    let tenant = Uuid::new_v4();
    {
        let bind = TenantId::from(tenant);
        let mut tx = pool.begin_tenant(&bind).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO {table} (tenant_id, body) VALUES ($1, 'secret')"
        ))
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let pool_clone = pool.clone();
    let table_clone = table.clone();
    let parent_tenant = TenantId::from(tenant);
    let leak = pool::scope_tenant(parent_tenant, async move {
        // Inside the parent's scope, spawn a child WITHOUT spawn_with_tenant.
        let p = pool_clone.clone();
        let t = table_clone.clone();
        tokio::spawn(async move {
            sqlx::query_as::<_, (String,)>(&format!("SELECT body FROM {t}"))
                .fetch_all(&p)
                .await
                .unwrap_or_default()
        })
        .await
        .unwrap()
    })
    .await;

    assert!(
        leak.is_empty(),
        "plain tokio::spawn inherited the tenant binding — pool hook bug. Got rows: {leak:?}"
    );

    drop_table(&pool, &table).await;
}

/// Attack 4: Concurrent requests with different tenants share the same
/// pool. Two tasks bind to T1 and T2, each insert one row, each read,
/// verify isolation under interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_tenants_do_not_cross_contaminate() {
    let pool = fresh_pool().await;
    let table = unique("adv_concurrent");
    create_isolated_table(&pool, &table).await;

    let t1 = Uuid::new_v4();
    let t2 = Uuid::new_v4();

    let mut handles = Vec::new();
    for (tenant, label) in [(t1, "from-t1"), (t2, "from-t2")] {
        let pool = pool.clone();
        let table = table.clone();
        handles.push(pool::spawn_with_tenant({
            let tenant = TenantId::from(tenant);
            async move {
                pool::scope_tenant(tenant.clone(), async move {
                    let mut tx = pool.begin_tenant(&tenant).await.unwrap();
                    for _ in 0..16 {
                        sqlx::query(&format!(
                            "INSERT INTO {table} (tenant_id, body) VALUES ($1, $2)"
                        ))
                        .bind(Uuid::parse_str(tenant.as_str()).unwrap())
                        .bind(label)
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                    }
                    let rows: Vec<(String,)> =
                        sqlx::query_as(&format!("SELECT body FROM {table}"))
                            .fetch_all(&mut *tx)
                            .await
                            .unwrap();
                    tx.commit().await.unwrap();
                    rows
                })
                .await
            }
        }));
    }

    for h in handles {
        let rows = h.await.unwrap();
        let labels: std::collections::BTreeSet<&str> =
            rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(
            labels.len(),
            1,
            "tenant saw rows from another tenant: {labels:?}"
        );
    }

    drop_table(&pool, &table).await;
}

/// Attack 5b: A policy that does not reference `current_setting(...)`
/// at all — e.g. `USING (TRUE)`. This is a real leak (every tenant sees
/// every row) but the audit's `policy_fail_open` finder only matches
/// `COALESCE(current_setting(...), ...)`, so this misconfiguration
/// slips through the audit.
///
/// **This test documents a KNOWN GAP**: it asserts the audit DOES NOT
/// flag `USING (TRUE)`, so any future change that closes the gap will
/// fail this test and force us to remove it. Tracked for v0.3+.
#[tokio::test]
async fn known_gap_audit_misses_policy_without_guc_reference() {
    use pg_rls::audit;

    let pool = fresh_pool().await;
    let table = unique("adv_known_gap");

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force");
    // Maximally permissive policy — every row visible to every tenant.
    sqlx::query(&format!(
        "CREATE POLICY tenant_iso ON {table} \
         USING (TRUE) WITH CHECK (TRUE)"
    ))
    .execute(&pool)
    .await
    .expect("policy");

    let report = audit::ensure_isolation(&pool).await.expect("audit");
    drop_table(&pool, &table).await;

    // The honest assertion: the audit doesn't catch this today. If a
    // future version of `audit` learns to flag policies whose USING
    // expression doesn't reference the configured GUC, this assertion
    // flips. Document by making the test fail when that happens.
    let flagged_in_fail_open = report
        .policy_fail_open
        .iter()
        .any(|p| p.table == table);
    assert!(
        !flagged_in_fail_open,
        "BREAKING — audit now catches `USING (TRUE)` policies. \
         Update CHANGELOG and remove this known-gap test."
    );
}

/// Attack 6: After a connection is released back to the pool, the next
/// checkout (with a different / no tenant) must NOT see the previous
/// tenant's binding. This exercises the after_release RESET hook.
#[tokio::test]
async fn released_connection_does_not_keep_stale_tenant() {
    let pool = fresh_pool().await;
    let table = unique("adv_release");
    create_isolated_table(&pool, &table).await;

    let secret_tenant = Uuid::new_v4();
    {
        let bind = TenantId::from(secret_tenant);
        let mut tx = pool.begin_tenant(&bind).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO {table} (tenant_id, body) VALUES ($1, 'top-secret')"
        ))
        .bind(secret_tenant)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // A subsequent admin-style query with NO tenant scope must fail
    // closed — see no rows, not the secret_tenant's data.
    let result: Result<Vec<(String,)>, _> = sqlx::query_as(&format!("SELECT body FROM {table}"))
        .fetch_all(&pool)
        .await;

    match result {
        Ok(rows) => {
            assert!(
                rows.is_empty(),
                "stale tenant binding exposed prior tenant's rows: {rows:?}"
            );
        }
        Err(e) => {
            // Also fine — fail closed via uuid cast on RESET'd GUC.
            let _ = e;
        }
    }

    drop_table(&pool, &table).await;
}
