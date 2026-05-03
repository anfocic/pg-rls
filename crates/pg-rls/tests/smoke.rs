use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use pg_rls::audit;
use pg_rls::pool;
use pg_rls::{PgPoolExt, TenantId};
use tower::ServiceExt;
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mtap_app:mtap_app@localhost:5433/mtap".to_string())
}

fn unique_suffix() -> String {
    Uuid::new_v4().simple().to_string()
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    table: String,
}

#[derive(Debug, Deserialize)]
struct NewNote {
    body: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Note {
    tenant_id: Uuid,
    body: String,
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn list_notes(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let sql = format!(
        "SELECT tenant_id, body FROM {} ORDER BY body ASC",
        state.table
    );
    let rows: Vec<(Uuid, String)> = sqlx::query_as(&sql)
        .fetch_all(&state.pool)
        .await
        .map_err(internal)?;
    let notes: Vec<Note> = rows
        .into_iter()
        .map(|(tenant_id, body)| Note { tenant_id, body })
        .collect();
    Ok(Json(notes))
}

async fn create_note(
    State(state): State<AppState>,
    tenant: TenantId,
    Json(input): Json<NewNote>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_uuid: Uuid = tenant.as_str().parse().map_err(internal)?;
    let sql = format!(
        "INSERT INTO {} (tenant_id, body) VALUES ($1, $2)",
        state.table
    );
    sqlx::query(&sql)
        .bind(tenant_uuid)
        .bind(input.body)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    Ok(StatusCode::CREATED)
}

async fn spawned_count(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pool = state.pool.clone();
    let sql = format!("SELECT COUNT(*) FROM {}", state.table);
    let count = pool::spawn_with_tenant(async move {
        sqlx::query_scalar::<_, i64>(&sql).fetch_one(&pool).await
    })
    .await
    .map_err(internal)?
    .map_err(internal)?;
    Ok(Json(count))
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/notes", get(list_notes).post(create_note))
        .route("/spawned-count", get(spawned_count))
        .layer(middleware::from_fn(pool::tenant_scope))
        .with_state(state)
}

async fn drop_table(pool: &PgPool, table: &str) {
    let sql = format!("DROP TABLE IF EXISTS {table} CASCADE");
    sqlx::query(&sql).execute(pool).await.expect("drop table");
}

#[tokio::test]
async fn consumer_smoke_test() {
    let pool = pool::with_tenant_hooks(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5)),
    )
    .connect(&db_url())
    .await
    .expect("connect");

    let table = format!("smoke_notes_{}", unique_suffix());
    let bad_table = format!("smoke_bad_{}", unique_suffix());

    sqlx::query(&format!(
        "CREATE TABLE {table} (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL, body TEXT NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create smoke table");
    sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("enable rls");
    sqlx::query(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force rls");
    sqlx::query(&format!(
        "CREATE POLICY tenant_isolation ON {table} \
         USING (tenant_id = current_setting('app.tenant_id', true)::uuid) \
         WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)"
    ))
    .execute(&pool)
    .await
    .expect("create policy");

    let tenant_a = TenantId::from(Uuid::new_v4());
    let tenant_b = TenantId::from(Uuid::new_v4());

    let mut tx = pool.begin_tenant(&tenant_a).await.expect("begin tenant a");
    sqlx::query(&format!(
        "INSERT INTO {table} (tenant_id, body) VALUES ($1, $2)"
    ))
    .bind(tenant_a.as_str().parse::<Uuid>().expect("tenant a uuid"))
    .bind("tenant-a-seed")
    .execute(&mut *tx)
    .await
    .expect("seed tenant a");
    tx.commit().await.expect("commit tenant a");

    let mut tx = pool.begin_tenant(&tenant_b).await.expect("begin tenant b");
    sqlx::query(&format!(
        "INSERT INTO {table} (tenant_id, body) VALUES ($1, $2)"
    ))
    .bind(tenant_b.as_str().parse::<Uuid>().expect("tenant b uuid"))
    .bind("tenant-b-seed")
    .execute(&mut *tx)
    .await
    .expect("seed tenant b");
    tx.commit().await.expect("commit tenant b");

    let app = app(AppState {
        pool: pool.clone(),
        table: table.clone(),
    });

    let req = Request::builder()
        .method("GET")
        .uri("/notes")
        .extension(tenant_a.clone())
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("list tenant a");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read list body");
    let notes: Vec<Note> = serde_json::from_slice(&body).expect("decode notes");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].tenant_id.to_string(), tenant_a.as_str());
    assert_eq!(notes[0].body, "tenant-a-seed");

    let req = Request::builder()
        .method("POST")
        .uri("/notes")
        .header("content-type", "application/json")
        .extension(tenant_a.clone())
        .body(Body::from(r#"{"body":"tenant-a-created"}"#))
        .expect("build create request");
    let resp = app.clone().oneshot(req).await.expect("create tenant a");
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method("GET")
        .uri("/spawned-count")
        .extension(tenant_a.clone())
        .body(Body::empty())
        .expect("build spawned-count request");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("spawned count tenant a");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read spawned-count body");
    let count: i64 = serde_json::from_slice(&body).expect("decode count");
    assert_eq!(count, 2);

    let report = audit::ensure_isolation(&pool)
        .await
        .expect("audit clean table");
    assert!(
        !report.rls_no_policy.iter().any(|t| t.table == table)
            && !report.policy_rls_off.iter().any(|t| t.table == table)
            && !report.policy_no_force.iter().any(|t| t.table == table)
            && !report.policy_no_with_check.iter().any(|p| p.table == table)
            && !report.policy_fail_open.iter().any(|p| p.table == table)
            && !report.tenant_col_no_policy.iter().any(|t| t.table == table),
        "expected clean smoke table `{table}` to be absent from audit findings:\n{report}"
    );

    sqlx::query(&format!(
        "CREATE TABLE {bad_table} (id UUID PRIMARY KEY, body TEXT)"
    ))
    .execute(&pool)
    .await
    .expect("create bad table");
    sqlx::query(&format!(
        "ALTER TABLE {bad_table} ENABLE ROW LEVEL SECURITY"
    ))
    .execute(&pool)
    .await
    .expect("enable bad rls");

    let report = audit::ensure_isolation(&pool)
        .await
        .expect("audit bad table");
    assert!(
        report.rls_no_policy.iter().any(|t| t.table == bad_table),
        "expected `{bad_table}` in rls_no_policy:\n{report}"
    );

    drop_table(&pool, &bad_table).await;
    drop_table(&pool, &table).await;
}
