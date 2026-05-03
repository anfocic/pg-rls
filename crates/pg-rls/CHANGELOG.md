# Changelog

All notable changes to `pg-rls` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-05-03

Hardening release: addresses the credibility gaps a senior reviewer would flag on 0.1.0. **No breaking source-level changes** for the default-feature configuration; bumped to 0.2 because `axum` moved from a hard dep to a default-on Cargo feature, which is technically a breaking change for the `Cargo.toml` of any downstream that disabled default features in some other dep tree.

### Added
- **`tracing` instrumentation.** Pool hooks emit `TRACE`-level events on every bind/release under the `pg_rls` target. `audit::ensure_isolation` runs inside an `INFO` span and emits a `WARN` event with finding counts when the report is non-empty. Plug into your existing `tracing-subscriber`; no extra wiring.
- **Property tests for the policy SQL emitter** (`tests/policy_property.rs`) — proptest, 256 cases per property, covering valid + invalid identifier shapes for table, schema, policy name, and cast type. Asserts the validator panics or the resulting SQL has no unbalanced quoting.
- **CI matrix on Postgres 14, 15, 16, 17.** Live audit and pool-hook tests now run against every supported PG version.
- **CI step builds and tests with `--no-default-features`** to prove the `axum`-free path keeps working.

### Changed
- **`axum` is now a default Cargo feature, not a hard dependency.** Disable with `default-features = false` to use `pg-rls` from Actix / warp / Rocket / no-framework code; the `pool` (sans `tenant_scope` middleware), `audit`, `policy`, and `tx` modules all work without axum. The `TenantId` data type stays available either way; only the `FromRequestParts` impl and the `tenant_scope` middleware are gated.
- **Crate description rewritten** to lead with the differentiator ("with the foot-guns already caught") rather than the generic stack listing.

### Internal
- Smoke test marked `required-features = ["axum"]` in `Cargo.toml` so it skips cleanly under `--no-default-features`.
- New `tests/adversarial.rs` integration suite — six probes that try to break the crate's promises (SQL injection via `TenantId` value, empty `TenantId`, plain `tokio::spawn` without `spawn_with_tenant`, concurrent distinct tenants on one pool, stale connection after release, audit's known gap on `USING (TRUE)` policies). All pass; the known-gap test pins current behaviour so a future audit improvement fails it and forces a CHANGELOG note.

### Known gaps (documented, not fixed in this release)
- `audit::ensure_isolation` does not detect policies whose USING expression doesn't reference the configured GUC at all (`USING (TRUE)`, `USING (1=1)`). Closing this requires parsing `pg_get_expr(polqual, polrelid)` and verifying it references `current_setting(<configured guc>, true)`. Tracked.

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

[Unreleased]: https://github.com/anfocic/pg-rls/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/anfocic/pg-rls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/anfocic/pg-rls/releases/tag/v0.1.0
