# pg-rls

[![ci](https://github.com/anfocic/pg-rls/actions/workflows/ci.yml/badge.svg)](https://github.com/anfocic/pg-rls/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pg-rls.svg)](https://crates.io/crates/pg-rls)
[![docs.rs](https://docs.rs/pg-rls/badge.svg)](https://docs.rs/pg-rls)

Tenant-isolation helpers for **Axum + sqlx + Postgres** apps that use **row-level security** for multi-tenancy.

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
      <td>same, but GUC name is <code>app.org_id</code>, schema is <code>app</code>, column is <code>org_id</code></td>
      <td>yes — <code>Tenancy::new().guc("app.org_id").schema("app").tenant_column("org_id")</code></td>
    </tr>
    <tr>
      <td>Actix / warp / Rocket</td>
      <td>the <code>pool</code> and <code>audit</code> modules are framework-agnostic; you'll write your own middleware (≈ 15 LOC)</td>
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

## What's in it

- **`TenantId`** — `String`-wrapping newtype with an Axum extractor that reads from a request `Extension`. Construct from anything via `From<Uuid>`, `From<i64>`, `From<&str>`, etc. Your auth layer fills the extension in.
- **Pool builder + middleware** that scope a Postgres GUC (default `app.tenant_id`) across a request's async call chain automatically. For background jobs and admin paths, `pool.begin_tenant(&tenant)` does the same per-transaction.
- **`Tenancy`** config struct — `.guc(...)`, `.schema(...)`, `.schemas(...)`, `.tenant_column(...)`. Defaults to `app.tenant_id`, `public`, `tenant_id`; override any to fit your codebase.
- **`audit::ensure_isolation(&pool)`** — boot-time invariant check. Reports tables with RLS-on-but-no-policy, policies missing `WITH CHECK`, fail-open `COALESCE` patterns, and tenant-tagged tables with no policy. **`audit::scan_migrations(path)`** is a lightweight CI lint that runs without a database and flags `CREATE POLICY` statements missing `WITH CHECK`.
- **`Tenancy::policy_template(table)`** — emits the canonical `ENABLE` / `FORCE` / `CREATE POLICY ... USING (...) WITH CHECK (...)` SQL sourced from your `Tenancy` config. The output is guaranteed to pass `ensure_isolation` clean, so you can stop hand-writing (and mis-writing) policy DDL in migrations. `.cast("uuid")` for non-text tenant columns.

JWT decoding and scope/permission middleware are deliberately out of scope — every app gets those wrong differently.

## What You Still Provide

- Authentication and tenant resolution logic.
- `TenantId` insertion into request extensions before `tenant_scope`.
- The actual RLS policy SQL in your migrations — or call `Tenancy::policy_template(table).cast("uuid").full_sql()` to emit the canonical shape and paste that into the migration.
- Explicit tenant binding on jobs, scripts, and spawned tasks outside the request path.

## Quick start

```rust
use sqlx::postgres::PgPoolOptions;
use pg_rls::pool;

let pool = pool::with_tenant_hooks(PgPoolOptions::new().max_connections(8))
    .connect(&database_url).await?;

// On boot, refuse to start if the schema is broken:
let report = pg_rls::audit::ensure_isolation(&pool).await?;
assert!(report.is_clean(), "RLS invariants broken:\n{report}");
```

If your stack uses different names:

```rust
use pg_rls::Tenancy;

let tenancy = Tenancy::new()
    .guc("app.org_id")
    .schema("app")
    .tenant_column("org_id");

let pool = tenancy
    .with_tenant_hooks(PgPoolOptions::new())
    .connect(&database_url).await?;

let report = tenancy.ensure_isolation(&pool).await?;
```

## Adoption Checklist

1. Wrap your pool with `pool::with_tenant_hooks(...)`.
2. Insert `TenantId` only after auth has resolved the correct tenant.
3. Add `pool::tenant_scope` on request paths that hit tenant data.
4. Use `pool::spawn_with_tenant` for spawned child tasks and `begin_tenant` / `set_tenant` for jobs.
5. Add `ENABLE`, `FORCE`, and a correct tenant policy to every tenant-scoped table.
6. Connect as a non-superuser role.
7. Run `pg_rls::audit::ensure_isolation(&pool)` at boot.
8. Keep the smoke path passing: `cargo test -p pg-rls --test smoke`.

## Example

[`examples/rls`](./examples/rls) covers the three RLS gotchas — `FORCE ROW LEVEL SECURITY`, non-superuser app role, and `WITH CHECK` — with three integration tests. One asserts the bug passes (leak demo); the others assert each fix.

```sh
docker compose up -d
export DATABASE_URL=postgres://mtap_app:mtap_app@localhost:5433/mtap
cargo test -p pg-rls-example
```

## Security

See [SECURITY.md](./SECURITY.md). Tenant-isolation bugs in this crate are in scope; bugs in your auth layer or your RLS policies are not.

## Failure Modes

- Wrong tenant resolved by auth:
  `pg-rls` will enforce whatever `TenantId` your auth layer supplies.
- A DB path bypasses the integration:
  raw pools, missing `tenant_scope`, plain `tokio::spawn`, and unscoped jobs can all skip the intended model.
- Broken RLS policy or deployment config:
  missing `FORCE`, disabled RLS, superuser roles, or semantically wrong predicates are still app/database failures.
- Side systems ignore the same contract:
  workers, scripts, or other services touching the same DB need the same tenancy discipline.

## Changelog

See [crates/pg-rls/CHANGELOG.md](./crates/pg-rls/CHANGELOG.md).

## License

MIT.
