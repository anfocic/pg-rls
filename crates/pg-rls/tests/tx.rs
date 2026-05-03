use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::time::Duration;
use pg_rls::{set_tenant, PgPoolExt, Tenancy, TenantId};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string())
}

#[tokio::test]
async fn default_set_tenant_sets_transaction_local_guc() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url())
        .await
        .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let mut tx = pool.begin().await.expect("begin");
    set_tenant(&mut tx, &tenant).await.expect("set tenant");

    let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
        .fetch_one(&mut *tx)
        .await
        .expect("read guc inside tx");
    let observed = row.get::<String, _>("v");

    assert_eq!(observed, expected);

    tx.commit().await.expect("commit");

    let row = sqlx::query("SELECT NULLIF(current_setting('app.tenant_id', true), '') AS v")
        .fetch_one(&pool)
        .await
        .expect("read guc after tx");
    let observed = row.get::<Option<String>, _>("v");

    assert_eq!(observed, None);
}

#[tokio::test]
async fn begin_tenant_honors_custom_guc_name() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url())
        .await
        .expect("connect");

    let tenancy = Tenancy::new().guc("app.org_id");
    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let mut tx = tenancy
        .begin_tenant(&pool, &tenant)
        .await
        .expect("begin tenant");

    let row = sqlx::query("SELECT current_setting('app.org_id', false) AS v")
        .fetch_one(&mut *tx)
        .await
        .expect("read custom guc");
    let observed = row.get::<String, _>("v");

    assert_eq!(observed, expected);
}

#[tokio::test]
async fn pg_pool_ext_begin_tenant_sets_default_guc() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url())
        .await
        .expect("connect");

    let tenant = TenantId::from(Uuid::new_v4());
    let expected = tenant.as_str().to_owned();

    let mut tx = pool.begin_tenant(&tenant).await.expect("begin tenant");

    let row = sqlx::query("SELECT current_setting('app.tenant_id', false) AS v")
        .fetch_one(&mut *tx)
        .await
        .expect("read default guc");
    let observed = row.get::<String, _>("v");

    assert_eq!(observed, expected);
}
