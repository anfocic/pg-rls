# Contributing

Thanks for considering a contribution. `pg-rls` is small and focused —
opinionated about what's in scope and what isn't — but the bar for
incoming changes is low if they're aligned with the README's "what's in
scope" list.

## Running tests locally

The integration tests need a Postgres reachable at the URL in
`DATABASE_URL`. The repo's `docker-compose.yml` brings up a Postgres 17
with the right schema and the non-superuser app role pg-rls needs:

```sh
docker compose up -d
export DATABASE_URL=postgres://mtap_app:mtap_app@localhost:5433/mtap
cargo test --workspace --all-targets
cargo test -p pg-rls --test smoke
```

The unit tests (lib + audit::scan_tests) don't need a database.

## Bar for a PR

CI runs six jobs. All must pass:

| job | what |
|---|---|
| test | `cargo test --workspace --all-targets` plus the explicit `cargo test -p pg-rls --test smoke` consumer-path smoke test against a fresh PG 17 |
| lint | `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` |
| docs | `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS="-D warnings"` |
| msrv | `cargo check` against the declared MSRV (1.88 today) |
| semver-checks | `cargo semver-checks` against the published version |
| audit | `cargo audit` against rustsec advisory DB |

If you add a new public type or method, make it `#[non_exhaustive]` if
it's a `struct` or `enum` that the user only consumes (never constructs
literally). The audit module's `Report`, `Lint`, `LintKind`, `TableName`,
and `PolicyRef` are the existing examples.

## Scope

In:
- Tenant-isolation hooks for sqlx + Postgres + Axum (or the framework-
  agnostic pool/audit pieces).
- Postgres-specific knobs that affect the tenant-isolation surface:
  schema config, GUC name, tenant column.
- Boot-time invariant checks (the `audit` module).

Out:
- JWT / session / auth code. Every app does this differently.
- RLS policy generation. The policy is one line of SQL; the user writes
  it.
- Permission / RBAC middleware. Use a tower layer of your own.
- Non-Postgres backends. RLS is a Postgres feature.

If you're not sure whether something is in scope, open an issue first.

## Bumping the version

`pg-rls` follows [SemVer](https://semver.org/). When making a change
that modifies the public surface:

1. Bump `version` in `crates/pg-rls/Cargo.toml`.
2. Move the `[Unreleased]` block in `crates/pg-rls/CHANGELOG.md` under
   the new version heading with a date.
3. Open the PR. CI's `semver-checks` job verifies the bump matches the
   API delta.

For a breaking change, bump major (or minor while pre-1.0).

## Reporting a security issue

See [SECURITY.md](./SECURITY.md). Don't open a public issue for a
tenant-isolation bug.
