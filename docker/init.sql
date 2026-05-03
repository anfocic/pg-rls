-- A non-superuser app role. RLS (even with FORCE) is bypassed by superusers,
-- so the application MUST connect as a regular role for tenant isolation
-- to actually be enforced. This is the gotcha that bites most people after
-- they remember to add FORCE: their app still connects as the database owner
-- which is also a superuser, and RLS is silently bypassed.
CREATE USER mtap_app WITH PASSWORD 'mtap_app';

GRANT CONNECT ON DATABASE mtap TO mtap_app;
GRANT USAGE, CREATE ON SCHEMA public TO mtap_app;

-- Tables created later (by sqlx migrate, running as mtap_app) will be owned
-- by mtap_app, which is what we want — FORCE RLS applies to owners too,
-- but only if the owner isn't a superuser.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO mtap_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO mtap_app;
