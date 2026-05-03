//! Pattern: row-level security with `FORCE ROW LEVEL SECURITY`.
//!
//! This example demonstrates two near-identical tables that differ only on
//! `FORCE ROW LEVEL SECURITY` + `WITH CHECK`:
//!
//! - `naive_notes` — has `ENABLE ROW LEVEL SECURITY` and a policy, but no
//!   `FORCE`. Because sqlx connects as the table owner, the policy is
//!   silently bypassed and tenants see each other's rows.
//! - `fixed_notes` — has `ENABLE` + `FORCE` + `WITH CHECK`. The policy
//!   applies to the owner too, and writes that try to forge another
//!   tenant's id are rejected.
//!
//! The proof tests in `tests/rls.rs` show the leak on `naive` and the
//! block on `fixed`.
//!
//! Both insert/list functions use [`pg_rls::PgPoolExt::begin_tenant`] to
//! open a tenant-scoped transaction in one line. They take the tenant as
//! a typed `Uuid` and bridge to [`pg_rls::TenantId`] at the call site —
//! this is the recommended pattern, since your domain types stay typed
//! and pg-rls sees the serialized form it stores in the GUC.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use pg_rls::{PgPoolExt, TenantId};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub body: String,
}

impl From<(Uuid, Uuid, String)> for Note {
    fn from((id, tenant_id, body): (Uuid, Uuid, String)) -> Self {
        Self {
            id,
            tenant_id,
            body,
        }
    }
}

pub async fn insert_naive(pool: &PgPool, tenant: Uuid, body: &str) -> sqlx::Result<Uuid> {
    let tenant_id = TenantId::from(tenant);
    let mut tx = pool.begin_tenant(&tenant_id).await?;
    let row: (Uuid,) =
        sqlx::query_as("INSERT INTO naive_notes (tenant_id, body) VALUES ($1, $2) RETURNING id")
            .bind(tenant)
            .bind(body)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(row.0)
}

pub async fn list_naive(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<Note>> {
    let tenant_id = TenantId::from(tenant);
    let mut tx = pool.begin_tenant(&tenant_id).await?;
    let rows: Vec<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, tenant_id, body FROM naive_notes")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(Note::from).collect())
}

pub async fn insert_fixed(pool: &PgPool, tenant: Uuid, body: &str) -> sqlx::Result<Uuid> {
    let tenant_id = TenantId::from(tenant);
    let mut tx = pool.begin_tenant(&tenant_id).await?;
    let row: (Uuid,) =
        sqlx::query_as("INSERT INTO fixed_notes (tenant_id, body) VALUES ($1, $2) RETURNING id")
            .bind(tenant)
            .bind(body)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(row.0)
}

pub async fn list_fixed(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<Note>> {
    let tenant_id = TenantId::from(tenant);
    let mut tx = pool.begin_tenant(&tenant_id).await?;
    let rows: Vec<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, tenant_id, body FROM fixed_notes")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(Note::from).collect())
}

#[derive(Deserialize)]
pub struct NewNote {
    body: String,
}

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/naive", post(create_naive).get(read_naive))
        .route("/fixed", post(create_fixed).get(read_fixed))
}

async fn create_naive(
    State(pool): State<PgPool>,
    tenant: TenantId,
    Json(input): Json<NewNote>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_uuid: Uuid = tenant.as_str().parse().map_err(internal)?;
    let id = insert_naive(&pool, tenant_uuid, &input.body)
        .await
        .map_err(internal)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

async fn read_naive(
    State(pool): State<PgPool>,
    tenant: TenantId,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_uuid: Uuid = tenant.as_str().parse().map_err(internal)?;
    let rows = list_naive(&pool, tenant_uuid).await.map_err(internal)?;
    Ok(Json(rows))
}

async fn create_fixed(
    State(pool): State<PgPool>,
    tenant: TenantId,
    Json(input): Json<NewNote>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_uuid: Uuid = tenant.as_str().parse().map_err(internal)?;
    let id = insert_fixed(&pool, tenant_uuid, &input.body)
        .await
        .map_err(internal)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

async fn read_fixed(
    State(pool): State<PgPool>,
    tenant: TenantId,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_uuid: Uuid = tenant.as_str().parse().map_err(internal)?;
    let rows = list_fixed(&pool, tenant_uuid).await.map_err(internal)?;
    Ok(Json(rows))
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
