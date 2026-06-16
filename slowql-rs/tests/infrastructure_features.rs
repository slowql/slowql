use slowql_lib::baseline::Baseline;
use slowql_lib::config::Config;
use slowql_lib::context::{classify_source, filter_issues_by_context, MIGRATION, TEST, ADHOC};
use slowql_lib::models::{AnalysisResult, Dimension, Issue, Location, Severity};
use slowql_lib::suppressions::parse_suppressions;

#[test]
fn config_loads_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.toml");
    std::fs::write(&path, r#"
[analysis]
dialect = "postgresql"

[severity]
fail_on = "critical"
"#).unwrap();

    let config = Config::from_toml(&path).unwrap();
    assert_eq!(config.analysis.dialect.as_deref(), Some("postgresql"));
    assert_eq!(config.severity.fail_on, "critical");
}

#[test]
fn config_loads_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.yaml");
    std::fs::write(&path, "analysis:\n  dialect: mysql\nseverity:\n  fail_on: high\n").unwrap();

    let config = Config::from_yaml(&path).unwrap();
    assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
    assert_eq!(config.severity.fail_on, "high");
}

#[test]
fn classify_context_paths() {
    assert_eq!(classify_source(Some("migrations/001.sql"), ""), MIGRATION);
    assert_eq!(classify_source(Some("tests/test_queries.sql"), ""), TEST);
    assert_eq!(classify_source(Some("queries.sql"), "SELECT 1"), ADHOC);
}

#[test]
fn inline_suppression_specific_rule() {
    let sql = "-- slowql: disable PERF-SCAN-001\nSELECT * FROM users";
    let map = parse_suppressions(sql);
    assert!(map.is_suppressed(2, "PERF-SCAN-001"));
    assert!(!map.is_suppressed(2, "SEC-INJ-001"));
}

#[test]
fn inline_suppression_all_rules() {
    let sql = "-- slowql: disable\nSELECT * FROM users";
    let map = parse_suppressions(sql);
    assert!(map.is_suppressed(2, "PERF-SCAN-001"));
    assert!(map.is_suppressed(2, "SEC-INJ-001"));
}

#[test]
fn context_filtering_migration() {
    let issues = vec![
        Issue::new("SEC-INJ-001", "sec", Severity::High, Dimension::Security, Location::new(1,1), "x"),
        Issue::new("PERF-SCAN-001", "perf", Severity::Medium, Dimension::Performance, Location::new(1,1), "x"),
        Issue::new("REL-DATA-001", "rel", Severity::Critical, Dimension::Reliability, Location::new(1,1), "x"),
    ];
    let filtered = filter_issues_by_context(issues, MIGRATION);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().any(|i| i.rule_id == "SEC-INJ-001"));
    assert!(filtered.iter().any(|i| i.rule_id == "REL-DATA-001"));
}

#[test]
fn baseline_roundtrip_and_filter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".slowql-baseline");

    let mut result = AnalysisResult::new();
    result.add_issue(Issue::new("TEST-001", "old issue", Severity::High, Dimension::Security, Location::new(1,1), "SELECT *"));
    result.add_issue(Issue::new("TEST-002", "new issue", Severity::Medium, Dimension::Performance, Location::new(2,1), "DELETE FROM t"));

    let baseline = Baseline::generate(&result);
    baseline.save(&path).unwrap();
    let loaded = Baseline::load(&path).unwrap();
    assert_eq!(loaded.entry_count, 2);

    let mut new_result = AnalysisResult::new();
    new_result.add_issue(Issue::new("TEST-001", "old issue", Severity::High, Dimension::Security, Location::new(1,1), "SELECT *"));
    new_result.add_issue(Issue::new("TEST-003", "brand new", Severity::Low, Dimension::Quality, Location::new(3,1), "x"));

    let (filtered, suppressed) = Baseline::filter_new(new_result, &loaded);
    assert_eq!(suppressed, 1);
    assert_eq!(filtered.issues.len(), 1);
    assert_eq!(filtered.issues[0].rule_id, "TEST-003");
}
