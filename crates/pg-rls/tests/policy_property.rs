//! Property tests proving the policy SQL emitter is injection-safe.
//!
//! `Tenancy::policy_template` formats validated identifiers into SQL.
//! The validator rejects anything outside ASCII alphanumerics + `_` and
//! the leading-character / length rules. These tests pin the contract
//! by feeding arbitrary strings through the builder and asserting:
//!
//! 1. Strings the validator accepts produce SQL with no unbalanced
//!    quotes and exactly the expected statement shapes.
//! 2. Strings the validator rejects always panic at builder time —
//!    they never reach the SQL formatter.
//!
//! If a future change loosens the validator, these tests should be the
//! first thing that fails.

use pg_rls::Tenancy;
use proptest::prelude::*;
use std::panic;

/// PG identifiers per the validator: 1..=63 chars, ASCII alphanumerics
/// or `_`, must start with a letter or `_`.
fn valid_identifier() -> impl Strategy<Value = String> {
    "[a-zA-Z_][a-zA-Z0-9_]{0,62}".prop_filter("non-empty", |s| !s.is_empty())
}

/// Anything that is *not* a valid identifier — strings that contain
/// disallowed bytes, are empty, or exceed length.
fn invalid_identifier() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        "[a-zA-Z]{64,80}",                           // too long
        "[0-9][a-zA-Z0-9_]*",                        // leading digit
        "[a-zA-Z_][a-zA-Z0-9_]*[^a-zA-Z0-9_][a-zA-Z0-9_]*", // disallowed char somewhere
        "[a-zA-Z_]*[';\"\\\\][a-zA-Z_]*",            // injection-flavoured chars
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn valid_identifiers_produce_well_formed_sql(
        table in valid_identifier(),
        schema in valid_identifier(),
        policy in valid_identifier(),
    ) {
        let tenancy = Tenancy::default();
        let sql = tenancy
            .policy_template(table.clone())
            .schema(schema.clone())
            .policy_name(policy.clone())
            .full_sql();

        // Statements must appear and be terminated.
        let enable = format!("ALTER TABLE \"{}\".\"{}\" ENABLE", schema, table);
        let force = format!("ALTER TABLE \"{}\".\"{}\" FORCE", schema, table);
        let create = format!("CREATE POLICY \"{}\" ON \"{}\".\"{}\"", policy, schema, table);
        prop_assert!(sql.contains(&enable));
        prop_assert!(sql.contains(&force));
        prop_assert!(sql.contains(&create));

        // No unbalanced quoting.
        prop_assert_eq!(sql.matches('"').count() % 2, 0, "unbalanced double-quotes:\n{}", sql);
        prop_assert_eq!(sql.matches('\'').count() % 2, 0, "unbalanced single-quotes:\n{}", sql);
    }

    #[test]
    fn invalid_identifiers_panic_at_builder_time(bad in invalid_identifier()) {
        // The validator panics; SQL formatting never runs.
        let result = panic::catch_unwind(|| {
            let tenancy = Tenancy::default();
            let _ = tenancy.policy_template(bad.clone()).full_sql();
        });
        prop_assert!(result.is_err(), "validator accepted invalid identifier {:?}", bad);
    }

    #[test]
    fn invalid_schema_overrides_panic(bad in invalid_identifier()) {
        let result = panic::catch_unwind(|| {
            let tenancy = Tenancy::default();
            let _ = tenancy.policy_template("orders").schema(bad.clone()).full_sql();
        });
        prop_assert!(result.is_err(), "validator accepted invalid schema {:?}", bad);
    }

    #[test]
    fn invalid_policy_name_overrides_panic(bad in invalid_identifier()) {
        let result = panic::catch_unwind(|| {
            let tenancy = Tenancy::default();
            let _ = tenancy
                .policy_template("orders")
                .policy_name(bad.clone())
                .full_sql();
        });
        prop_assert!(result.is_err(), "validator accepted invalid policy name {:?}", bad);
    }

    #[test]
    fn invalid_cast_panics(bad in invalid_identifier()) {
        let result = panic::catch_unwind(|| {
            let tenancy = Tenancy::default();
            let _ = tenancy
                .policy_template("orders")
                .cast(bad.clone())
                .full_sql();
        });
        prop_assert!(result.is_err(), "validator accepted invalid cast type {:?}", bad);
    }
}
