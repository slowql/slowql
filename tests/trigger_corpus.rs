//! Trigger corpus: verifies each rule ID fires on its expected SQL.
//! Ported from Python tests/e2e/trigger_corpus.py

use slowql_lib::engine::Engine;

fn check(sql: &str, dialect: Option<&str>, expected_rule: &str) -> bool {
    let mut config = slowql_lib::config::Config::default();
    // Use contextual mode for trigger tests (testing rule behavior, not confidence filtering)
    config.analysis.min_confidence = "contextual".to_string();
    // Enable compliance frameworks for compliance rules
    if expected_rule.starts_with("COMP-") {
        config
            .analysis
            .compliance_frameworks
            .insert("gdpr".to_string());
        config
            .analysis
            .compliance_frameworks
            .insert("hipaa".to_string());
        config
            .analysis
            .compliance_frameworks
            .insert("pci-dss".to_string());
        config
            .analysis
            .compliance_frameworks
            .insert("sox".to_string());
    }
    let engine = Engine::new(config);
    // Use a file path to set context to "application" (not "adhoc")
    let result = engine.analyze(sql, dialect, Some("src/queries.sql"));
    result.issues.iter().any(|i| i.rule_id == expected_rule)
}

// Security rules
#[test]
fn trigger_sec_inj_001() {
    assert!(check(
        "SELECT * FROM users WHERE name = 'x' + user_input",
        None,
        "SEC-INJ-001"
    ));
}
#[test]
fn trigger_sec_inj_002() {
    assert!(check("EXEC('SELECT 1')", None, "SEC-INJ-002"));
}
#[test]
fn trigger_sec_inj_003() {
    assert!(check(
        "SELECT * FROM u WHERE id=1 OR 1=1",
        None,
        "SEC-INJ-003"
    ));
}
#[test]
fn trigger_sec_inj_004() {
    assert!(check("SELECT SLEEP(5)", None, "SEC-INJ-004"));
}
#[test]
fn trigger_sec_auth_001() {
    assert!(check(
        "SELECT * WHERE password='secret'",
        None,
        "SEC-AUTH-001"
    ));
}
#[test]
fn trigger_sec_auth_002() {
    assert!(check("GRANT SELECT ON t TO PUBLIC", None, "SEC-AUTH-002"));
}
#[test]
fn trigger_sec_auth_005() {
    assert!(check("GRANT ALL ON schema TO hacker", None, "SEC-AUTH-005"));
}

// Performance rules
#[test]
fn trigger_perf_scan_001() {
    assert!(check(
        "SELECT * FROM users WHERE id = 1",
        None,
        "PERF-SCAN-001"
    ));
}
#[test]
fn trigger_perf_scan_002() {
    assert!(check("DELETE FROM users", None, "PERF-SCAN-002"));
}
#[test]
fn trigger_perf_idx_002() {
    assert!(check(
        "SELECT * FROM users WHERE name LIKE '%john%'",
        None,
        "PERF-IDX-002"
    ));
}
#[test]
fn trigger_perf_join_001() {
    assert!(check("SELECT * FROM a CROSS JOIN b", None, "PERF-JOIN-001"));
}
#[test]
fn trigger_perf_agg_001() {
    assert!(check("SELECT COUNT(*) FROM users", None, "PERF-AGG-001"));
}

// Reliability rules
#[test]
fn trigger_rel_data_001() {
    assert!(check("DELETE FROM orders", None, "REL-DATA-001"));
}
#[test]
fn trigger_rel_data_002() {
    assert!(check("TRUNCATE TABLE users", None, "REL-DATA-002"));
}
#[test]
fn trigger_rel_data_004() {
    assert!(check(
        "DROP TABLE users",
        Some("postgresql"),
        "REL-DATA-004"
    ));
}

// Compliance rules
#[test]
fn trigger_comp_gdpr_001() {
    assert!(check(
        "SELECT email, name FROM users WHERE id = 1",
        None,
        "COMP-GDPR-001"
    ));
}
#[test]
fn trigger_comp_pci_002() {
    assert!(check(
        "INSERT INTO payments (card_number, cvv) VALUES ('4111111111111111', '123')",
        None,
        "COMP-PCI-002"
    ));
}
#[test]
fn trigger_comp_sox_001() {
    assert!(check(
        "DELETE FROM ledger WHERE id = 1",
        None,
        "COMP-SOX-001"
    ));
}

// Cost rules
#[test]
fn trigger_cost_compute_001() {
    assert!(check("SELECT * FROM users", None, "COST-COMPUTE-001"));
}
#[test]
fn trigger_cost_bq_001() {
    assert!(check(
        "SELECT * FROM dataset.table",
        Some("bigquery"),
        "COST-BQ-001"
    ));
}
#[test]
fn trigger_cost_sf_001() {
    assert!(check(
        "SELECT * FROM db.schema.table",
        Some("snowflake"),
        "COST-SF-001"
    ));
}

// Quality rules
#[test]
fn trigger_qual_null_001() {
    assert!(check(
        "SELECT * FROM t WHERE x = NULL",
        None,
        "QUAL-NULL-001"
    ));
}
#[test]
fn trigger_qual_modern_004() {
    assert!(check(
        "SELECT CASE WHEN x=1 THEN 'a' END FROM t",
        None,
        "QUAL-MODERN-004"
    ));
}
#[test]
fn trigger_qual_schema_004() {
    assert!(check(
        "CREATE TABLE t (price FLOAT)",
        None,
        "QUAL-SCHEMA-004"
    ));
}

// Migration rules
#[test]
fn trigger_mig_brk_001() {
    assert!(check("DROP TABLE users", Some("postgresql"), "MIG-BRK-001"));
}

// Dialect-specific rules
#[test]
fn trigger_perf_mysql_002() {
    assert!(check(
        "SELECT * FROM t ORDER BY RAND() LIMIT 1",
        Some("mysql"),
        "PERF-MYSQL-002"
    ));
}
#[test]
fn trigger_rel_mysql_001() {
    assert!(check(
        "INSERT IGNORE INTO t VALUES (1)",
        Some("mysql"),
        "REL-MYSQL-001"
    ));
}
#[test]
fn trigger_sec_pg_001() {
    assert!(check(
        "SELECT pg_sleep(5)",
        Some("postgresql"),
        "SEC-PG-001"
    ));
}
#[test]
fn trigger_perf_lock_001() {
    assert!(check(
        "SELECT * FROM t WITH (TABLOCK)",
        Some("tsql"),
        "PERF-LOCK-001"
    ));
}
