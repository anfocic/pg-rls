//! No-DB unit tests for the policy SQL emitter.
//!
//! These pin the exact string shape so changes to the helper output are
//! visible in diffs. A separate integration test
//! (`audit_db::policy_template_round_trip`) confirms the same output
//! passes `ensure_isolation` on a live Postgres.

use pg_rls::Tenancy;

#[test]
fn default_template_emits_canonical_three_statements() {
    let sql = Tenancy::default().policy_template("orders").full_sql();

    let expected = "\
ALTER TABLE \"public\".\"orders\" ENABLE ROW LEVEL SECURITY;
ALTER TABLE \"public\".\"orders\" FORCE ROW LEVEL SECURITY;
CREATE POLICY \"tenant_isolation\" ON \"public\".\"orders\"
  USING (\"tenant_id\" = current_setting('app.tenant_id', true))
  WITH CHECK (\"tenant_id\" = current_setting('app.tenant_id', true));
";

    assert_eq!(sql, expected);
}

#[test]
fn cast_is_applied_to_current_setting() {
    let sql = Tenancy::default()
        .policy_template("orders")
        .cast("uuid")
        .create_policy_sql();

    assert!(
        sql.contains("current_setting('app.tenant_id', true)::uuid"),
        "expected uuid cast in:\n{sql}"
    );
}

#[test]
fn custom_guc_and_tenant_column_flow_into_predicate() {
    let sql = Tenancy::new()
        .guc("app.org_id")
        .tenant_column("org_id")
        .policy_template("members")
        .cast("uuid")
        .full_sql();

    let expected = "\
ALTER TABLE \"public\".\"members\" ENABLE ROW LEVEL SECURITY;
ALTER TABLE \"public\".\"members\" FORCE ROW LEVEL SECURITY;
CREATE POLICY \"tenant_isolation\" ON \"public\".\"members\"
  USING (\"org_id\" = current_setting('app.org_id', true)::uuid)
  WITH CHECK (\"org_id\" = current_setting('app.org_id', true)::uuid);
";

    assert_eq!(sql, expected);
}

#[test]
fn schema_and_policy_name_overrides() {
    let sql = Tenancy::default()
        .policy_template("members")
        .schema("app")
        .policy_name("members_isolation")
        .full_sql();

    assert!(sql.contains("ALTER TABLE \"app\".\"members\" ENABLE"));
    assert!(sql.contains("CREATE POLICY \"members_isolation\" ON \"app\".\"members\""));
}

#[test]
fn individual_sql_helpers_terminate_with_semicolon() {
    let tenancy = Tenancy::default();
    let t = tenancy.policy_template("orders");
    assert!(t.enable_rls_sql().ends_with(';'));
    assert!(t.force_rls_sql().ends_with(';'));
    assert!(t.create_policy_sql().ends_with(';'));
}

#[test]
#[should_panic(expected = "invalid char")]
fn rejects_bad_table_identifier() {
    let _ = Tenancy::default().policy_template("ord;ers");
}

#[test]
#[should_panic(expected = "invalid char")]
fn rejects_bad_policy_name() {
    let _ = Tenancy::default()
        .policy_template("orders")
        .policy_name("a-b");
}

#[test]
#[should_panic(expected = "invalid char")]
fn rejects_bad_cast_type() {
    let _ = Tenancy::default()
        .policy_template("orders")
        .cast("uuid; DROP TABLE foo");
}

#[test]
#[should_panic(expected = "invalid char")]
fn rejects_bad_schema() {
    let _ = Tenancy::default().policy_template("orders").schema("bad-schema");
}
