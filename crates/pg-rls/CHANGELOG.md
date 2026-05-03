# Changelog

All notable changes to `pg-rls` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-03

Initial release under the `pg-rls` name. Evolved from the `tenaxum` crate (0.1–0.2 on crates.io); renamed to drop the framework-specific suffix in advance of `axum` becoming an optional feature. The 0.1.0 surface is what `tenaxum` 0.2.0 shipped plus the policy SQL helper prepared as `tenaxum` 0.3.

### Public surface

- **`TenantId`** — `String`-wrapping newtype with an Axum `FromRequestParts` extractor that reads from request `Extension`. Construct from anything via `From<Uuid>`, `From<i32>`, `From<i64>`, `From<u32>`, `From<u64>`, `From<i128>`, `From<u128>`, `From<String>`, `From<&str>`. `TenantId::new(impl Into<String>)` for everything else. `&TenantId` is the preferred form for arguments — the type is `Clone` but not `Copy`.
- **`Tenancy`** config struct with `.guc(...)`, `.schema(...)`, `.schemas(...)`, `.tenant_column(...)`. All identifiers validated at builder time (PG identifier rules, ≤ 63 chars). Invalid values panic — these are developer constants, not user input. `Tenancy::default()` reproduces the conventional shape (`app.tenant_id`, `public`, `tenant_id`).
- **Pool hooks** — `pool::with_tenant_hooks(opts)` (default config) / `Tenancy::with_tenant_hooks(opts)` (configured). Installs `before_acquire`, `after_release`, and `after_connect` so the configured GUC is set on every connection checkout and reset on release. The `after_connect` hook handles freshly-opened connections that sqlx 0.8 doesn't fire `before_acquire` for. `pool::tenant_after_connect_hook(&mut conn)` lets you compose with your own `after_connect`.
- **Pool middleware** — `pool::tenant_scope` Axum middleware that reads `TenantId` from request extensions and scopes a tokio task-local for the handler chain. `pool::scope_tenant`, `pool::spawn_with_tenant`, `pool::current_tenant` for non-middleware paths.
- **Transaction helpers** — `PgPoolExt::begin_tenant(&tenant)` / `Tenancy::begin_tenant(&pool, &tenant)` opens a transaction and `SET LOCAL`s the GUC inside it. `set_tenant(&mut tx, &tenant)` / `Tenancy::set_tenant(&mut tx, &tenant)` for cases where a transaction is already open.
- **`audit::ensure_isolation(&pool)`** / `Tenancy::ensure_isolation(&pool)` — boot-time invariant check. Reports tables with RLS-enabled-but-no-policy, policy-attached-but-RLS-off, RLS-on-but-no-FORCE, missing `WITH CHECK`, fail-open `COALESCE` patterns, and tenant-tagged tables with no policy. `Report` and the leaf types are `#[non_exhaustive]`.
- **`audit::scan_migrations(path)`** / `Tenancy::scan_migrations(path)` — lightweight CI lint that walks `*.sql` and flags `CREATE POLICY` statements missing `WITH CHECK`. Hand-rolled scanner; not a security guarantee.
- **`policy::PolicyTemplate`** / `Tenancy::policy_template(table)` — emits the canonical `ENABLE` / `FORCE` / `CREATE POLICY ... USING (...) WITH CHECK (...)` SQL sourced from the configured `Tenancy`. Output is guaranteed to pass `ensure_isolation` clean. `.cast("uuid")` for non-text tenant columns; `.schema(...)` and `.policy_name(...)` overrides.

### Migrating from `tenaxum`

`tenaxum 0.2.0` users upgrading to `pg-rls 0.1.0`:

1. `Cargo.toml`: `tenaxum = "0.2"` → `pg-rls = "0.1"`.
2. Imports: `use tenaxum::...` → `use pg_rls::...`.
3. No API changes. Rename only.

The `tenaxum` 0.2.0 crate stays published unchanged; no further versions ship under that name.

[Unreleased]: https://github.com/anfocic/pg-rls/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/anfocic/pg-rls/releases/tag/v0.1.0
