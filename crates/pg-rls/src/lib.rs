//! # pg-rls
//!
//! Tenant-isolation helpers for Axum + sqlx + Postgres apps that use
//! row-level security for multi-tenancy.
//!
//! `pg-rls` exists for one narrow job: carry a tenant identifier from
//! your Rust request/job context into Postgres so row-level security
//! policies can enforce tenant isolation at the database boundary.
//!
//! The crate has three main pieces:
//!
//! 1. [`pool`] — request-scoped pool hooks for the common Axum/sqlx path
//! 2. [`PgPoolExt`] / [`set_tenant`] — explicit transaction-scoped binding
//!    for jobs, scripts, or admin paths
//! 3. [`audit`] — boot-time and CI-time checks for common RLS mistakes
//!
//! ## Minimum safe setup
//!
//! 1. Connect as a **non-superuser** Postgres role.
//! 2. Add `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` to
//!    your tenant-scoped tables.
//! 3. Use either [`pool::with_tenant_hooks`] + [`pool::tenant_scope`] or
//!    [`PgPoolExt::begin_tenant`] / [`set_tenant`] on every DB path.
//! 4. Run [`audit::ensure_isolation`] at boot and fail closed if it
//!    returns findings.
//!
//! ## Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use axum::{middleware, Router};
//! use sqlx::postgres::PgPoolOptions;
//! use pg_rls::{audit, pool};
//!
//! let pool = pool::with_tenant_hooks(PgPoolOptions::new().max_connections(8))
//!     .connect("postgres://...").await?;
//!
//! let report = audit::ensure_isolation(&pool).await?;
//! if !report.is_clean() {
//!     panic!("RLS invariants broken at boot:\n{report}");
//! }
//!
//! let app: Router = Router::new()
//!     .route("/", axum::routing::get(|| async { "ok" }))
//!     .layer(middleware::from_fn(pool::tenant_scope))
//!     .with_state(pool);
//! # let _ = app;
//! # Ok(()) }
//! ```
//!
//! Your auth layer inserts `TenantId` into request extensions:
//! `req.extensions_mut().insert(TenantId::from(...))`. The middleware
//! scopes that value for the async call chain; the pool hooks read it and
//! set the configured Postgres GUC.
//!
//! ## What you still provide
//!
//! `pg-rls` removes the repetitive tenant-plumbing around sqlx and
//! Postgres RLS, but it still assumes your app supplies four things:
//!
//! - **Authentication and tenant resolution.** Your auth/session layer
//!   must decide which tenant the caller belongs to.
//! - **`TenantId` insertion.** For request-scoped usage, your middleware
//!   inserts `TenantId` into request extensions before
//!   [`pool::tenant_scope`] runs.
//! - **RLS policy SQL in your migrations.** Either hand-write the
//!   `USING` / `WITH CHECK` predicates or generate the canonical shape
//!   from [`Tenancy::policy_template`].
//! - **Non-request wiring.** Jobs, scripts, queue consumers, and spawned
//!   tasks still need [`PgPoolExt::begin_tenant`], [`set_tenant`], or
//!   [`pool::spawn_with_tenant`] on the DB paths that should be scoped.
//!
//! ## Adoption checklist
//!
//! If you want the "install it and stop thinking about tenant plumbing"
//! path, this is the checklist:
//!
//! 1. Wrap your pool builder with [`pool::with_tenant_hooks`].
//! 2. Insert [`TenantId`] only after auth has resolved the correct
//!    tenant for the caller.
//! 3. Add [`pool::tenant_scope`] to the request path before handlers that
//!    touch tenant-scoped data.
//! 4. Use [`pool::spawn_with_tenant`] for spawned child tasks, and
//!    [`PgPoolExt::begin_tenant`] / [`set_tenant`] for jobs and scripts.
//! 5. Add `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and a
//!    correct tenant policy to every tenant-scoped table.
//! 6. Connect as a **non-superuser** role in every environment.
//! 7. Run [`audit::ensure_isolation`] at boot and fail closed on findings.
//! 8. Keep the smoke path passing: `cargo test -p pg-rls --test smoke`.
//!
//! ## Async model
//!
//! Tenant binding is stored in a Tokio task-local. That means it flows
//! through ordinary async calls, but **does not automatically cross**
//! [`tokio::spawn`] boundaries. For spawned child tasks, use
//! [`pool::spawn_with_tenant`] or manually wrap the future with
//! [`pool::scope_tenant`].
//!
//! ```no_run
//! # async fn run(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//! use axum::extract::State;
//! use pg_rls::pool;
//!
//! async fn fan_out(State(pool): State<sqlx::PgPool>) -> sqlx::Result<()> {
//!     let child_pool = pool.clone();
//!     pool::spawn_with_tenant(async move {
//!         sqlx::query("SELECT 1").execute(&child_pool).await
//!     })
//!     .await
//!     .expect("spawned task panicked")?;
//!     Ok(())
//! }
//! # let _ = fan_out;
//! # Ok(()) }
//! ```
//!
//! ## Audit model
//!
//! [`audit::ensure_isolation`] is the real safety check: it inspects the
//! live schema and reports common tenant-isolation mistakes.
//!
//! [`audit::scan_migrations`] is intentionally weaker. It is a
//! lightweight CI lint for obvious `CREATE POLICY ...` omissions, not a
//! full SQL parser and not a security guarantee.
//!
//! ## Failure modes and mitigations
//!
//! The common places an app can still fail are:
//!
//! - **Wrong tenant resolved by auth.**
//!   Mitigation: keep tenant resolution in one place, test it directly,
//!   and only insert [`TenantId`] after auth has verified membership.
//! - **A DB path bypasses the integration.**
//!   Mitigation: wrap the pool once at construction time, use
//!   [`pool::tenant_scope`] consistently, and treat jobs/spawned tasks as
//!   first-class integration points rather than exceptions.
//! - **Broken RLS policy or deployment config.**
//!   Mitigation: use `FORCE`, avoid superuser roles, and run
//!   [`audit::ensure_isolation`] on boot.
//! - **Side systems ignore the same contract.**
//!   Mitigation: make workers, scripts, and maintenance paths use the
//!   same non-superuser role and the same tenant-binding helpers.
//!
//! ## What pg-rls cannot guarantee
//!
//! - It does **not** prove your RLS predicates are semantically correct.
//!   A syntactically valid policy can still be wrong.
//! - It does **not** make superuser connections safe. Postgres superusers
//!   bypass RLS unconditionally.
//! - It does **not** make [`audit::scan_migrations`] equivalent to a
//!   live-schema audit.
//! - It does **not** authenticate users or derive tenant identity for
//!   you. It assumes the [`TenantId`] you provide is already correct.
//!
//! ## Configuration
//!
//! Every assumption is configurable through [`Tenancy`] — the GUC name
//! (`app.tenant_id`), schema list (`public`), and tenant-column name
//! (`tenant_id`) all default to common values, and any can be overridden.
//! [`Tenancy::default`] reproduces the conventional shape.
//!
//! ## Pattern 1 — pool-scoped (recommended for production apps)
//!
//! Set the GUC once when a connection is checked out of the pool, reset
//! it on release. Every query in the scoped async call chain is
//! auto-isolated. Zero per-call-site boilerplate.
//!
//! See [`pool`] for the [`pool::with_tenant_hooks`] free fn (default
//! config) and [`Tenancy::with_tenant_hooks`] for the configured form, plus
//! the [`pool::tenant_scope`] Axum middleware.
//!
//! ## Pattern 2 — explicit `begin_tenant`
//!
//! Open a transaction and `SET LOCAL` the GUC inside it. Useful for
//! background jobs, one-off scripts, or admin paths where the pool hooks
//! aren't wired.
//!
//! See [`PgPoolExt::begin_tenant`] (default config), [`Tenancy::begin_tenant`]
//! (configured), and [`set_tenant`] / [`Tenancy::set_tenant`].
//!
//! ## Pattern 3 — boot-time invariant audit
//!
//! Refuse to start the app on a broken schema. See [`audit::ensure_isolation`]
//! / [`Tenancy::ensure_isolation`] and [`audit::scan_migrations`] /
//! [`Tenancy::scan_migrations`].
//!
//! ## Pattern 4 — canonical policy SQL
//!
//! Generate the `ENABLE` / `FORCE` / `CREATE POLICY ... USING (...) WITH
//! CHECK (...)` DDL from your [`Tenancy`] config so the GUC name and
//! tenant column match what [`audit::ensure_isolation`] accepts as clean.
//! See [`Tenancy::policy_template`] and [`PolicyTemplate`].
//!
//! ## What pg-rls deliberately does not do
//!
//! - **JWT decoding or session verification.** Every app does this
//!   differently. Decode in your own middleware, then
//!   `req.extensions_mut().insert(TenantId::from(...))`.
//! - **Scope or permission middleware.** Tenant scoping is necessary but
//!   not sufficient for authorization; per-resource permission checks
//!   are out of scope here.
//! - **Cross-database support.** RLS is a Postgres feature; this crate
//!   is sqlx-and-Postgres-only by design.

pub mod audit;
mod config;
mod extractor;
pub mod policy;
pub mod pool;
mod tx;

pub use config::Tenancy;
pub use extractor::TenantId;
pub use policy::PolicyTemplate;
pub use tx::{set_tenant, PgPoolExt};
