use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::Path;
use std::time::Duration;
use pg_rls::TenantId;
use pg_rls_example::{insert_fixed, Note};
use tower::ServiceExt;
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
async fn fixed_route_returns_only_the_current_tenants_rows() {
    let pool = pool().await;
    let tenant = Uuid::new_v4();
    insert_fixed(&pool, tenant, "tenant note")
        .await
        .expect("seed row");

    let app = pg_rls_example::router().with_state(pool);
    let req = Request::builder()
        .method("GET")
        .uri("/fixed")
        .extension(TenantId::from(tenant))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("handle request");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let notes: Vec<Note> = serde_json::from_slice(&body).expect("decode note list");

    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].tenant_id, tenant);
    assert_eq!(notes[0].body, "tenant note");
}
