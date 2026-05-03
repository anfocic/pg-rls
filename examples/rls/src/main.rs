use axum::{routing::get, Router};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    Migrator::new(Path::new("./examples/rls/migrations"))
        .await?
        .run(&pool)
        .await?;

    let app = Router::new()
        .route("/", get(|| async { "pg-rls-example" }))
        .nest("/notes", pg_rls_example::router())
        .with_state(pool);

    let addr: SocketAddr = "0.0.0.0:3000".parse()?;
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
