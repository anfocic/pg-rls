//! Pool-scoped tenant isolation: set the configured GUC (default
//! `app.tenant_id`) once when a connection is checked out of the pool,
//! reset it when it goes back. Every query made in the scoped async call
//! chain is auto-isolated, with no per-call-site boilerplate.
//!
//! This is the pattern most production codebases want. It pairs with:
//!
//! 1. The [`TENANT_ID`] task-local — set per-request by the
//!    [`tenant_scope`] middleware below.
//! 2. The [`with_tenant_hooks`] free fn (default-config) or the
//!    [`crate::Tenancy::with_tenant_hooks`] method (custom config) — wires
//!    `before_acquire` / `after_release` / `after_connect` hooks that
//!    read the task-local and run `set_config` / `RESET` on the
//!    connection.
//!
//! ## Default-config wiring (most apps)
//!
//! ```no_run
//! # async fn run() -> sqlx::Result<()> {
//! use sqlx::postgres::PgPoolOptions;
//! use pg_rls::pool;
//!
//! let pool = pool::with_tenant_hooks(PgPoolOptions::new().max_connections(8))
//!     .connect("postgres://...").await?;
//! # Ok(()) }
//! ```
//!
//! ## Custom-config wiring (different GUC name, e.g. `app.org_id`)
//!
//! ```no_run
//! # async fn run() -> sqlx::Result<()> {
//! use sqlx::postgres::PgPoolOptions;
//! use pg_rls::Tenancy;
//!
//! let pool = Tenancy::new()
//!     .guc("app.org_id")
//!     .with_tenant_hooks(PgPoolOptions::new().max_connections(8))
//!     .connect("postgres://...").await?;
//! # Ok(()) }
//! ```
//!
//! ## Axum middleware
//!
//! ```ignore
//! use axum::{Router, middleware};
//! use pg_rls::pool::tenant_scope;
//!
//! let app = Router::new()
//!     // ...your routes...
//!     .layer(middleware::from_fn(tenant_scope));
//! ```
//!
//! `tenant_scope` reads `Extension<TenantId>` (set by your auth layer) and
//! scopes the [`TENANT_ID`] task-local for the rest of the request. The
//! pool hooks then pick it up automatically on every connection checkout.
//!
//! The middleware is GUC-agnostic — it only sets the task-local. The hooks
//! (which know the GUC name) read from the task-local. So a single
//! `tenant_scope` middleware works for any [`crate::Tenancy`] configuration.
//!
//! ## Spawned tasks
//!
//! Tokio task-locals do **not** propagate across [`tokio::spawn`]. If a
//! handler fans DB work out into spawned tasks, use [`spawn_with_tenant`]
//! (or manually wrap the future in [`scope_tenant`]) so the child task
//! inherits the current tenant binding.
//!
//! ## When to use this vs [`crate::PgPoolExt::begin_tenant`]
//!
//! - **Pool hooks** (this module): for the common case where every
//!   handler in your app touches tenant-scoped data and you want
//!   isolation by default.
//! - **`begin_tenant`**: for explicit, scoped uses — background jobs
//!   that operate on a specific tenant outside of an HTTP request,
//!   one-off scripts, or admin paths where the pool hooks aren't wired.
//!
//! ## Composing with your own `after_connect`
//!
//! `with_tenant_hooks` installs three hooks: `before_acquire`,
//! `after_release`, and `after_connect`. `after_connect` is a scalar
//! setter on `PgPoolOptions`, so if **you** call `.after_connect(..)`
//! after the hooks are installed, **your** hook replaces pg-rls's — and
//! a fresh connection will not have the GUC set when its first query
//! runs (sqlx 0.8 only fires `before_acquire` for connections already in
//! the idle pool, not for newly-opened ones).
//!
//! Use [`tenant_after_connect_hook`] (default config) or
//! [`crate::Tenancy::after_connect`] (custom) from inside your own
//! `after_connect` closure to keep pg-rls's behaviour:
//!
//! ```no_run
//! # async fn run() -> sqlx::Result<()> {
//! use sqlx::postgres::PgPoolOptions;
//! use pg_rls::pool;
//!
//! let opts = pool::with_tenant_hooks(PgPoolOptions::new())
//!     .after_connect(|conn, _meta| Box::pin(async move {
//!         sqlx::query("SET statement_timeout = '5s'")
//!             .execute(&mut *conn).await?;
//!         pool::tenant_after_connect_hook(conn).await?;
//!         Ok(())
//!     }));
//! # let _ = opts;
//! # Ok(()) }
//! ```

use crate::config::Tenancy;
use crate::TenantId;
#[cfg(feature = "axum")]
use axum::{body::Body, http::Request, middleware::Next, response::Response};
use sqlx::postgres::{PgConnection, PgPoolOptions};
use std::future::Future;
use tokio::task::JoinHandle;

tokio::task_local! {
    /// Per-request tenant binding. Set by [`tenant_scope`] middleware (or
    /// any code that opens a [`tokio::task_local::LocalKey::scope`] block
    /// over it). Read by the pool hooks.
    pub static TENANT_ID: TenantId;
}

impl Tenancy {
    /// Apply pg-rls pool hooks to a [`PgPoolOptions`] builder, using
    /// this [`Tenancy`]'s `guc_name`.
    ///
    /// Three hooks are installed:
    ///
    /// - `before_acquire`: reads [`TENANT_ID`] task-local; if set, runs
    ///   `SELECT set_config(<guc>, <tenant>, false)` (session-level —
    ///   because the connection may be used outside an explicit
    ///   transaction). If unset, runs `RESET <guc>` so a connection that
    ///   previously held a tenant binding can't leak it into the new
    ///   request.
    /// - `after_release`: unconditionally runs `RESET <guc>` before the
    ///   connection returns to the pool. Defense in depth.
    /// - `after_connect`: mirrors the `before_acquire` SET on
    ///   freshly-opened connections. sqlx 0.8 only fires `before_acquire`
    ///   for connections already in the idle pool, so without this hook
    ///   a fresh checkout under fail-closed RLS errors with
    ///   `unrecognized configuration parameter`.
    pub fn with_tenant_hooks(&self, opts: PgPoolOptions) -> PgPoolOptions {
        let guc_for_acquire = self.guc_name.clone();
        let guc_for_release = self.guc_name.clone();
        let guc_for_connect = self.guc_name.clone();
        opts.before_acquire(move |conn, _meta| {
            let guc = guc_for_acquire.clone();
            Box::pin(async move {
                apply_tenant_guc(conn, &guc).await?;
                Ok(true)
            })
        })
        .after_release(move |conn, _meta| {
            let guc = guc_for_release.clone();
            Box::pin(async move {
                let sql = format!("RESET {guc}");
                sqlx::query(&sql).execute(&mut *conn).await.map(|_| true)
            })
        })
        .after_connect(move |conn, _meta| {
            let guc = guc_for_connect.clone();
            Box::pin(async move { mirror_guc_if_set(conn, &guc).await })
        })
    }

    /// Free-function form of [`tenant_after_connect_hook`] bound to this
    /// `Tenancy`'s GUC name. Use from inside your own `after_connect`
    /// closure when you have custom per-connection setup that would
    /// otherwise clobber pg-rls's hook.
    pub async fn after_connect(&self, conn: &mut PgConnection) -> sqlx::Result<()> {
        mirror_guc_if_set(conn, &self.guc_name).await
    }
}

/// Apply pg-rls pool hooks to a [`PgPoolOptions`] builder using the
/// default [`Tenancy`] (`app.tenant_id`).
///
/// Equivalent to `Tenancy::default().with_tenant_hooks(opts)`. Use the
/// [`Tenancy`] builder directly if you need a custom GUC name.
pub fn with_tenant_hooks(opts: PgPoolOptions) -> PgPoolOptions {
    Tenancy::default().with_tenant_hooks(opts)
}

/// Free function that mirrors the `before_acquire` SET on a fresh
/// connection, using the default GUC (`app.tenant_id`).
///
/// Public so callers who need their own `after_connect` callback (e.g.
/// to set `statement_timeout`) can compose pg-rls's behaviour into
/// theirs — sqlx 0.8 stores `after_connect` as a single callback, so
/// multiple `.after_connect(..)` calls overwrite each other.
///
/// If [`TENANT_ID`] is set, runs `set_config('app.tenant_id', <id>, false)`.
/// If unset, leaves the connection untouched. For a custom GUC name, use
/// [`crate::Tenancy::after_connect`].
pub async fn tenant_after_connect_hook(conn: &mut PgConnection) -> sqlx::Result<()> {
    Tenancy::default().after_connect(conn).await
}

/// `PgPoolOptions` pre-wired with [`with_tenant_hooks`] (default config)
/// and a small connection cap, suitable for integration tests.
///
/// Equivalent to:
///
/// ```ignore
/// with_tenant_hooks(PgPoolOptions::new().max_connections(2))
/// ```
///
/// For custom-config tests, use `Tenancy::new().<knobs>.with_tenant_hooks(...)`
/// directly.
pub fn test_pool_options() -> PgPoolOptions {
    with_tenant_hooks(PgPoolOptions::new().max_connections(2))
}

/// Returns the tenant currently bound in [`TENANT_ID`], if any.
///
/// Useful when request-scoped code needs to propagate the current tenant
/// into another future or task explicitly.
pub fn current_tenant() -> Option<TenantId> {
    TENANT_ID.try_with(Clone::clone).ok()
}

/// Run `future` inside a [`TENANT_ID`] scope.
///
/// This is the manual form of what [`tenant_scope`] does for an Axum
/// request. Use it when tenant-scoped work starts outside the middleware
/// path, or when you need to re-bind the tenant around a child future.
pub async fn scope_tenant<F>(tenant: TenantId, future: F) -> F::Output
where
    F: Future,
{
    TENANT_ID.scope(tenant, future).await
}

/// Spawn a task that inherits the current [`TENANT_ID`] binding, if any.
///
/// Tokio task-locals do not cross [`tokio::spawn`] boundaries on their
/// own. This helper captures the current tenant and re-scopes the child
/// future so pool hooks continue to see the expected binding.
pub fn spawn_with_tenant<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let tenant = current_tenant();
    tokio::spawn(async move {
        match tenant {
            Some(tenant) => scope_tenant(tenant, future).await,
            None => future.await,
        }
    })
}

/// Axum middleware that scopes the [`TENANT_ID`] task-local for the
/// duration of the request.
///
/// Reads `Extension<TenantId>` off the request — your auth layer is
/// expected to have inserted it. If absent, the request runs with no
/// tenant binding (the pool hooks will run `RESET` on every checkout,
/// which is the correct behavior for unauthenticated or admin paths).
///
/// GUC-agnostic: this middleware sets the task-local, the pool hooks
/// (which know the GUC name) read it. A single `tenant_scope` works for
/// any [`crate::Tenancy`] configuration.
#[cfg(feature = "axum")]
pub async fn tenant_scope(req: Request<Body>, next: Next) -> Response {
    match req.extensions().get::<TenantId>().cloned() {
        Some(tenant) => scope_tenant(tenant, next.run(req)).await,
        None => next.run(req).await,
    }
}

async fn apply_tenant_guc(conn: &mut PgConnection, guc: &str) -> sqlx::Result<()> {
    match TENANT_ID.try_with(|t| t.0.clone()) {
        Ok(value) => {
            tracing::trace!(target: "pg_rls", guc, tenant = %value, "binding tenant GUC on checkout");
            sqlx::query("SELECT set_config($1, $2, false)")
                .bind(guc)
                .bind(value)
                .execute(&mut *conn)
                .await?;
        }
        Err(_) => {
            tracing::trace!(target: "pg_rls", guc, "no tenant bound — resetting GUC on checkout");
            let sql = format!("RESET {guc}");
            sqlx::query(&sql).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

async fn mirror_guc_if_set(conn: &mut PgConnection, guc: &str) -> sqlx::Result<()> {
    if let Ok(value) = TENANT_ID.try_with(|t| t.0.clone()) {
        tracing::trace!(target: "pg_rls", guc, tenant = %value, "mirroring tenant GUC into new connection");
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(guc)
            .bind(value)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_with_tenant_propagates_binding() {
        let expected = TenantId::new("acme-co");
        let observed = scope_tenant(expected.clone(), async move {
            spawn_with_tenant(async { current_tenant() })
                .await
                .expect("join child task")
        })
        .await;

        assert_eq!(observed, Some(expected));
    }

    #[tokio::test]
    async fn plain_spawn_does_not_propagate_binding() {
        let observed = scope_tenant(TenantId::new("acme-co"), async move {
            tokio::spawn(async { current_tenant() })
                .await
                .expect("join child task")
        })
        .await;

        assert_eq!(observed, None);
    }
}
