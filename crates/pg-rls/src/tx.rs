//! Explicit transaction-scoped tenant binding.
//!
//! This is the right path when you are not inside the request-scoped pool
//! hook model from [`crate::pool`]: background jobs, one-off scripts,
//! admin tasks, queue consumers, or any code that already owns a
//! transaction and wants to scope a subset of work to one tenant.
//!
//! ## Default-config example
//!
//! ```no_run
//! # async fn run(pool: sqlx::PgPool, tenant: pg_rls::TenantId) -> sqlx::Result<()> {
//! use pg_rls::PgPoolExt;
//!
//! let mut tx = pool.begin_tenant(&tenant).await?;
//! sqlx::query("SELECT 1").execute(&mut *tx).await?;
//! tx.commit().await?;
//! # Ok(()) }
//! ```
//!
//! ## Custom-config example
//!
//! ```no_run
//! # async fn run(pool: sqlx::PgPool, tenant: pg_rls::TenantId) -> sqlx::Result<()> {
//! use pg_rls::Tenancy;
//!
//! let tenancy = Tenancy::new().guc("app.org_id");
//! let mut tx = tenancy.begin_tenant(&pool, &tenant).await?;
//! sqlx::query("SELECT 1").execute(&mut *tx).await?;
//! tx.commit().await?;
//! # Ok(()) }
//! ```

use crate::config::Tenancy;
use crate::TenantId;
use sqlx::{PgPool, Postgres, Transaction};
use std::future::Future;

impl Tenancy {
    /// Set this `Tenancy`'s GUC on an open transaction via
    /// `SELECT set_config(..., true)` (transaction-scoped).
    ///
    /// Useful when you already have a transaction in flight and need to
    /// scope a sub-block to a specific tenant. Most call sites should
    /// prefer [`Tenancy::begin_tenant`] which begins the transaction for
    /// you.
    pub async fn set_tenant<'c>(
        &self,
        tx: &mut Transaction<'c, Postgres>,
        tenant: &TenantId,
    ) -> sqlx::Result<()> {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(self.guc_name.as_ref())
            .bind(tenant.as_str())
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Begin a transaction on `pool` and set this `Tenancy`'s GUC to
    /// `tenant`.
    ///
    /// The returned transaction is identical to one from [`PgPool::begin`];
    /// the only difference is that `SET LOCAL <guc> = '<id>'` has already
    /// been run inside it.
    pub async fn begin_tenant<'p>(
        &self,
        pool: &'p PgPool,
        tenant: &TenantId,
    ) -> sqlx::Result<Transaction<'p, Postgres>> {
        let mut tx = pool.begin().await?;
        self.set_tenant(&mut tx, tenant).await?;
        Ok(tx)
    }
}

/// Set the default GUC (`app.tenant_id`) on an open transaction via
/// `SET LOCAL`.
///
/// Equivalent to `Tenancy::default().set_tenant(tx, tenant)`. Use the
/// [`Tenancy`](crate::Tenancy) form if you need a custom GUC name.
///
/// ## `SET LOCAL` vs the pool-hook path
///
/// This function uses `set_config(..., true)` — the third argument
/// `true` makes the binding **transaction-scoped**. When the tx ends
/// (commit or rollback), the connection returns to the pool with no
/// lingering tenant binding.
///
/// The pool-hook path in [`crate::pool`] uses `set_config(..., false)`
/// (session-scoped) instead, because pool-checked-out connections can be
/// used outside an explicit transaction; the hooks compensate by running
/// `RESET <guc>` on `after_release`. The asymmetry is intentional —
/// pick the form that matches your call site:
///
/// | path | scope arg | reset by |
/// |------|-----------|----------|
/// | this function (in a tx) | `true` (LOCAL) | tx commit / rollback |
/// | `pool::with_tenant_hooks` | `false` (SESSION) | `after_release` hook |
pub async fn set_tenant<'c>(
    tx: &mut Transaction<'c, Postgres>,
    tenant: &TenantId,
) -> sqlx::Result<()> {
    Tenancy::default().set_tenant(tx, tenant).await
}

/// Extension trait on [`sqlx::PgPool`] adding tenant-scoped transaction
/// helpers using the default [`Tenancy`].
///
/// Written as `-> impl Future<...> + Send` rather than `async fn` so the
/// returned future is `Send`-bounded — required for callers spawning the
/// future onto a multi-threaded runtime.
///
/// For a custom GUC name, use [`Tenancy::begin_tenant`] directly.
#[allow(clippy::manual_async_fn)]
pub trait PgPoolExt {
    /// Begin a transaction and set the default GUC (`app.tenant_id`) to
    /// the given tenant.
    ///
    /// This is the recommended API for non-request work when you want
    /// tenant isolation without wiring request-scoped pool hooks.
    ///
    /// Pair with a Postgres RLS policy on your tenant-scoped tables:
    ///
    /// ```sql
    /// CREATE POLICY tenant_isolation ON your_table
    ///     USING       (tenant_id = current_setting('app.tenant_id', true)::uuid)
    ///     WITH CHECK  (tenant_id = current_setting('app.tenant_id', true)::uuid);
    /// ```
    ///
    /// Don't forget `ALTER TABLE your_table FORCE ROW LEVEL SECURITY` —
    /// without it, the table owner (which sqlx connects as) bypasses the
    /// policy and your isolation is silently broken.
    ///
    /// And — even with FORCE — your application must connect as a
    /// non-superuser role. Superusers bypass RLS unconditionally, FORCE
    /// or not.
    ///
    /// For a pre-existing transaction, use [`set_tenant`] instead.
    fn begin_tenant<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> impl Future<Output = sqlx::Result<Transaction<'a, Postgres>>> + Send + 'a;
}

impl PgPoolExt for PgPool {
    #[allow(clippy::manual_async_fn)]
    fn begin_tenant<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> impl Future<Output = sqlx::Result<Transaction<'a, Postgres>>> + Send + 'a {
        async move { Tenancy::default().begin_tenant(self, tenant).await }
    }
}
