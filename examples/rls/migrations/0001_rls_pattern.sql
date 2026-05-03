-- Two tables, both with a tenant_id and an RLS policy.
-- The only difference: naive_notes does NOT have FORCE ROW LEVEL SECURITY.
--
-- ENABLE ROW LEVEL SECURITY applies the policy to ordinary users.
-- It does NOT apply to the table owner (or superusers), unless FORCE is set.
-- sqlx connects as the database owner, so naive_notes silently bypasses RLS
-- and leaks across tenants. fixed_notes does not.

CREATE TABLE naive_notes (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    body      TEXT NOT NULL
);

ALTER TABLE naive_notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_naive ON naive_notes
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE TABLE fixed_notes (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    body      TEXT NOT NULL
);

ALTER TABLE fixed_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE fixed_notes FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_fixed ON fixed_notes
    USING       (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK  (tenant_id = current_setting('app.tenant_id', true)::uuid);
