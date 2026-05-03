# Security policy

## Reporting a vulnerability

If you believe you've found a tenant-isolation bug or any other security
issue in `pg-rls`, please report it privately:

- Email: **andrej@fole.dev** (PGP optional; reach out and I'll send a key
  if you want one).
- Or open a [GitHub Security Advisory](https://github.com/anfocic/pg-rls/security/advisories/new)
  on this repository.

Please **do not** open a public issue or PR for a vulnerability — that
publishes the bug before a fix lands.

## What's in scope

`pg-rls` exists to help downstream apps achieve tenant isolation when
combined with Postgres RLS. The following are in scope:

- **Tenant leakage in `pg-rls`'s own pool hooks** — e.g. a connection
  returned to the pool with `app.tenant_id` still set to a previous
  tenant, or a fresh checkout running queries with no GUC and silently
  matching all rows under fail-open RLS.
- **`begin_tenant` / `set_tenant` not actually scoping the transaction.**
- **`audit::ensure_isolation` failing to detect a class of broken
  schemas it claims to detect.**
- **`audit::scan_migrations` parser bugs** that miss a real
  `CREATE POLICY ... <missing WITH CHECK>` or that produce false
  negatives on syntactically valid SQL.

## What's out of scope

- **Your auth layer.** Decoding JWTs, mapping users to tenants,
  CSRF, session management — `pg-rls` deliberately doesn't ship
  any of these. Bugs in your auth layer are bugs in your app.
- **The RLS policies you write.** A policy that references a column
  that doesn't exist, or compares against `0` instead of the GUC, is a
  bug in your migration. `audit::ensure_isolation` flags some classes
  of bad policy but is not exhaustive — it raises the floor, not the
  ceiling.
- **Postgres itself, sqlx, axum, or any other upstream dependency.**
  Report those upstream.
- **Your application connecting as a Postgres superuser.** Superusers
  bypass RLS unconditionally; `pg-rls`'s docs and example explicitly
  call this out. Connecting as a superuser is a deployment misconfig,
  not a `pg-rls` bug.

## Response

- Acknowledgement: within 72 hours.
- Triage and timeline: within 7 days.
- Fix released as a patch version (e.g. `0.1.x`) for active minor lines.
  Backports to older minors only if the bug is a tenant leak.

## Disclosure

Coordinated. I'll work with you on a public advisory once a fixed
version is on crates.io. Credit goes to the reporter unless you ask
for anonymity.
