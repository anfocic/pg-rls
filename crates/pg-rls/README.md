# pg-rls

[![crates.io](https://img.shields.io/crates/v/pg-rls.svg)](https://crates.io/crates/pg-rls)
[![docs.rs](https://docs.rs/pg-rls/badge.svg)](https://docs.rs/pg-rls)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Tenant-isolation helpers for Axum + sqlx + Postgres apps that use row-level security for multi-tenancy.

## Is this for you?

<table>
  <colgroup>
    <col width="45%">
    <col width="55%">
  </colgroup>
  <thead>
    <tr><th align="left">your stack</th><th align="left">works?</th></tr>
  </thead>
  <tbody>
    <tr>
      <td>Axum 0.8 + sqlx 0.8 + Postgres + RLS</td>
      <td>yes — drop-in</td>
    </tr>
    <tr>
      <td>same, but tenant ID is <code>i64</code> / slug / <code>String</code></td>
      <td>yes — <code>TenantId::from(your_id)</code></td>
    </tr>
    <tr>
      <td>same, but GUC is <code>app.org_id</code>, schema is <code>app</code>, column is <code>org_id</code></td>
      <td>yes — <code>Tenancy::new().guc("app.org_id").schema("app").tenant_column("org_id")</code></td>
    </tr>
    <tr>
      <td>Actix / warp / Rocket</td>
      <td>the <code>pool</code>, <code>audit</code>, and <code>policy</code> modules are framework-agnostic; bring your own ~15 LOC of middleware</td>
    </tr>
    <tr>
      <td>Diesel, SeaORM, or any non-sqlx</td>
      <td>no — sqlx-specific</td>
    </tr>
    <tr>
      <td>MySQL, SQLite, anything not Postgres</td>
      <td>no — RLS is a Postgres feature</td>
    </tr>
    <tr>
      <td>application-level isolation (no RLS)</td>
      <td>no — this crate is specifically for RLS</td>
    </tr>
  </tbody>
</table>

## Minimum safe setup

1. Connect as a **non-superuser** Postgres role.
2. `ENABLE` and `FORCE` row-level security on every tenant-scoped table, with a policy that gates both `USING` and `WITH CHECK` on a `current_setting(...)` GUC. (Or: have `Tenancy::policy_template` emit it for you.)
3. Wire `pool::with_tenant_hooks(...)` + `pool::tenant_scope` on request paths, or `begin_tenant` / `set_tenant` on jobs and admin paths.
4. Run `audit::ensure_isolation(&pool)` at boot and fail closed on findings.

## Quick start

```rust
use axum::{middleware, routing::get, Router};
use sqlx::postgres::PgPoolOptions;
use pg_rls::{audit, pool, TenantId};

let pool = pool::with_tenant_hooks(PgPoolOptions::new().max_connections(8))
    .connect(&database_url).await?;

// Refuse to start on a broken schema.
let report = audit::ensure_isolation(&pool).await?;
assert!(report.is_clean(), "RLS invariants broken at boot:\n{report}");

let app = Router::new()
    .route("/notes", get(list_notes))
    .layer(middleware::from_fn(pool::tenant_scope))
    .with_state(pool);
```

Your auth layer inserts `Extension<TenantId>` once it has resolved the caller's tenant. The middleware reads it, scopes a Tokio task-local for the handler chain, and the pool hooks set the configured Postgres GUC on every connection checkout. Handlers don't need any per-call ceremony — every `sqlx` query they run is auto-isolated.

For spawned child tasks, use `pool::spawn_with_tenant(...)` so the binding crosses the `tokio::spawn` boundary.

## Configuration

Defaults: GUC `app.tenant_id`, schema `public`, tenant column `tenant_id`, audit + bind treated as one consistent set. Override any of them through `Tenancy`:

```rust
use pg_rls::Tenancy;

let tenancy = Tenancy::new()
    .guc("app.org_id")
    .schema("app")
    .tenant_column("org_id");

let pool   = tenancy.with_tenant_hooks(PgPoolOptions::new()).connect(&database_url).await?;
let report = tenancy.ensure_isolation(&pool).await?;
```

All identifiers are validated at builder time (PG identifier rules, ≤ 63 chars). Invalid input panics — these are developer-set constants, not user input.

`TenantId` wraps a `String` with `From` impls for `Uuid`, `i32`, `i64`, `u32`, `u64`, `i128`, `u128`, `String`, and `&str`. Bridge to your typed key at the call site.

## Boot-time audit

`audit::ensure_isolation` walks the live schema and reports the common RLS misconfigurations: tables with RLS enabled but no policy attached, policies attached without RLS enabled, RLS without `FORCE`, `WITH CHECK` missing on write commands, fail-open `COALESCE(current_setting(...), ...)` patterns, and tenant-tagged tables with no policy. `Report` is `#[non_exhaustive]`; treat any non-empty finding as fail-closed at boot.

```rust
let report = pg_rls::audit::ensure_isolation(&pool).await?;
if !report.is_clean() {
    panic!("RLS invariants broken at boot:\n{report}");
}
```

For CI runs without a database, `audit::scan_migrations("migrations")` walks `*.sql` files and flags `CREATE POLICY` statements missing `WITH CHECK`. It is a hand-rolled syntactic lint — not a SQL parser, not a security guarantee.

## Canonical policy SQL

`Tenancy::policy_template(table)` emits the `ENABLE` / `FORCE` / `CREATE POLICY ... USING (...) WITH CHECK (...)` shape sourced from the configured GUC and tenant column. Output is guaranteed to pass `ensure_isolation` clean:

```rust
let sql = Tenancy::default()
    .policy_template("orders")
    .cast("uuid")        // omit for text tenant columns
    .full_sql();
// Paste into your migration, or pipe each statement through sqlx::query.
```

`.schema(...)` and `.policy_name(...)` override the defaults (`public` and `tenant_isolation`). All identifiers validated at builder time.

## Background jobs and admin paths

The pool hooks only fire on connection checkout from within an `Extension<TenantId>`-scoped request. For queue consumers, scripts, and admin paths, bind explicitly with `begin_tenant`:

```rust
use pg_rls::{PgPoolExt, TenantId};

let tenant: TenantId = TenantId::from(tenant_uuid);
let mut tx = pool.begin_tenant(&tenant).await?;
let rows: Vec<(uuid::Uuid, String)> =
    sqlx::query_as("SELECT id, body FROM notes")
        .fetch_all(&mut *tx).await?;
tx.commit().await?;
```

`set_tenant(&mut tx, &tenant)` for cases where a transaction is already open. `Tenancy::begin_tenant` and `Tenancy::set_tenant` for non-default configs.

## Adoption checklist

1. Wrap your pool with `pool::with_tenant_hooks(...)`.
2. Insert `TenantId` into request extensions only after auth has resolved the correct tenant.
3. Add `pool::tenant_scope` to every request path that hits tenant-scoped data.
4. Use `pool::spawn_with_tenant` for spawned child tasks; `begin_tenant` / `set_tenant` for jobs and admin paths.
5. `ENABLE`, `FORCE`, and a tenant policy on every tenant-scoped table — `Tenancy::policy_template` emits the canonical shape.
6. Connect as a **non-superuser** Postgres role in every environment. Superusers bypass RLS unconditionally.
7. Run `audit::ensure_isolation(&pool)` at boot and fail closed on findings.

## Failure modes the crate cannot prevent

- **Wrong tenant resolved by auth.** `pg-rls` enforces whatever `TenantId` you hand it. Centralize tenant resolution and test it directly.
- **A DB path that bypasses the integration.** Raw pools, missing `tenant_scope`, plain `tokio::spawn`, and unscoped jobs all skip the model. Treat jobs and spawned tasks as first-class integration paths, not exceptions.
- **Broken RLS policy or deployment config.** Missing `FORCE`, disabled RLS, superuser roles, or semantically wrong predicates are still your bug to catch — `audit::ensure_isolation` flags the common cases.
- **Side systems ignoring the same contract.** Workers, scripts, and other services touching the same DB need the same role and binding helpers.

## What's not in the crate

- **JWT decoding or session verification.** Your auth layer does that, then sets `Extension<TenantId>`.
- **Scope or permission middleware.** Tenant scoping is necessary but not sufficient for authorization.
- **Cross-database support.** Postgres only; sqlx only.

## Compatibility

- Rust **1.88+** (MSRV).
- `axum = "0.8"`, `sqlx = "0.8"` (with `runtime-tokio` and the `postgres` feature).
- Postgres 14+ (any version with RLS — practically every supported release).

## Security

See [SECURITY.md](https://github.com/anfocic/pg-rls/blob/main/SECURITY.md). Tenant-isolation bugs in this crate are in scope; bugs in your auth layer or your RLS policies are not.

## License

MIT.
