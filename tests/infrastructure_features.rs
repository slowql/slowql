use slowql_lib::baseline::Baseline;
use slowql_lib::config::Config;
use slowql_lib::context::{
    classify_source, filter_issues_by_context, APPLICATION, MIGRATION, TEST,
};
use slowql_lib::models::{AnalysisResult, Dimension, Issue, Location, Severity};
use slowql_lib::suppressions::parse_suppressions;

#[test]
fn config_loads_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.toml");
    std::fs::write(
        &path,
        r#"
[analysis]
dialect = "postgresql"

[severity]
fail_on = "critical"
"#,
    )
    .unwrap();

    let config = Config::from_toml(&path).unwrap();
    assert_eq!(config.analysis.dialect.as_deref(), Some("postgresql"));
    assert_eq!(config.severity.fail_on, "critical");
}

#[test]
fn config_loads_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.yaml");
    std::fs::write(
        &path,
        "analysis:\n  dialect: mysql\nseverity:\n  fail_on: high\n",
    )
    .unwrap();

    let config = Config::from_yaml(&path).unwrap();
    assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
    assert_eq!(config.severity.fail_on, "high");
}

#[test]
fn classify_context_paths() {
    assert_eq!(classify_source(Some("migrations/001.sql"), ""), MIGRATION);
    assert_eq!(classify_source(Some("tests/test_queries.sql"), ""), TEST);
    assert_eq!(
        classify_source(Some("queries.sql"), "SELECT 1"),
        APPLICATION
    );
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
        Issue::new(
            "SEC-INJ-001",
            "sec",
            Severity::High,
            Dimension::Security,
            Location::new(1, 1),
            "x",
        ),
        Issue::new(
            "PERF-SCAN-001",
            "perf",
            Severity::Medium,
            Dimension::Performance,
            Location::new(1, 1),
            "x",
        ),
        Issue::new(
            "REL-DATA-001",
            "rel",
            Severity::Critical,
            Dimension::Reliability,
            Location::new(1, 1),
            "x",
        ),
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
    result.add_issue(Issue::new(
        "TEST-001",
        "old issue",
        Severity::High,
        Dimension::Security,
        Location::new(1, 1),
        "SELECT *",
    ));
    result.add_issue(Issue::new(
        "TEST-002",
        "new issue",
        Severity::Medium,
        Dimension::Performance,
        Location::new(2, 1),
        "DELETE FROM t",
    ));

    let baseline = Baseline::generate(&result);
    baseline.save(&path).unwrap();
    let loaded = Baseline::load(&path).unwrap();
    assert_eq!(loaded.entry_count, 2);

    let mut new_result = AnalysisResult::new();
    new_result.add_issue(Issue::new(
        "TEST-001",
        "old issue",
        Severity::High,
        Dimension::Security,
        Location::new(1, 1),
        "SELECT *",
    ));
    new_result.add_issue(Issue::new(
        "TEST-003",
        "brand new",
        Severity::Low,
        Dimension::Quality,
        Location::new(3, 1),
        "x",
    ));

    let (filtered, suppressed) = Baseline::filter_new(new_result, &loaded);
    assert_eq!(suppressed, 1);
    assert_eq!(filtered.issues.len(), 1);
    assert_eq!(filtered.issues[0].rule_id, "TEST-003");
}

#[test]
fn config_loads_table_metadata_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.yaml");
    std::fs::write(
        &path,
        r#"
analysis:
  dialect: postgresql
  table_metadata:
    large_tables:
      - transactions
      - events
    partitioned_tables:
      transactions:
        - created_at
      events:
        - event_date
"#,
    )
    .unwrap();

    let config = Config::from_yaml(&path).unwrap();
    assert_eq!(config.analysis.table_metadata.large_tables.len(), 2);
    assert!(config
        .analysis
        .table_metadata
        .large_tables
        .contains(&"transactions".to_string()));
    assert!(config
        .analysis
        .table_metadata
        .large_tables
        .contains(&"events".to_string()));
    assert_eq!(config.analysis.table_metadata.partitioned_tables.len(), 2);
    let tx_cols = config
        .analysis
        .table_metadata
        .partitioned_tables
        .get("transactions")
        .unwrap();
    assert_eq!(tx_cols, &vec!["created_at".to_string()]);
    let ev_cols = config
        .analysis
        .table_metadata
        .partitioned_tables
        .get("events")
        .unwrap();
    assert_eq!(ev_cols, &vec!["event_date".to_string()]);
}

#[test]
fn config_default_table_metadata_is_empty() {
    let config = Config::default();
    assert!(config.analysis.table_metadata.large_tables.is_empty());
    assert!(config.analysis.table_metadata.partitioned_tables.is_empty());
}

#[test]
fn adhoc_unbounded_select_no_perf_scan_003() {
    use slowql_lib::engine::Engine;
    let engine = Engine::with_default_config();
    // stdin = no file path = adhoc context
    let result = engine.analyze("SELECT * FROM users", Some("postgresql"), None);
    assert!(
        !result.issues.iter().any(|i| i.rule_id == "PERF-SCAN-003"),
        "PERF-SCAN-003 should not fire in adhoc context"
    );
}

#[test]
fn application_unbounded_select_fires_perf_scan_003() {
    use slowql_lib::engine::Engine;
    let engine = Engine::with_default_config();
    // .sql file = application context
    let result = engine.analyze(
        "SELECT id FROM users",
        Some("postgresql"),
        Some("app/queries.sql"),
    );
    assert!(
        result.issues.iter().any(|i| i.rule_id == "PERF-SCAN-003"),
        "PERF-SCAN-003 should fire in application context"
    );
}

#[test]
fn registry_has_all_rules() {
    use slowql_lib::engine::Engine;
    let engine = Engine::with_default_config();
    assert!(engine.rule_count() >= 280);
}

#[test]
fn registry_filter_by_dimension() {
    use slowql_lib::engine::Engine;
    let engine = Engine::with_default_config();
    let sec_rules = engine.registry_ref().for_dimension("security");
    assert!(sec_rules.len() >= 50);
    for rule in sec_rules {
        assert_eq!(rule.dimension().as_str(), "security");
    }
}

#[test]
fn scoring_from_config() {
    use slowql_lib::config::ComplexityConfig;
    use slowql_lib::scoring::ComplexityScorer;
    let config = ComplexityConfig {
        enabled: true,
        threshold_optimal: 30,
        threshold_complex: 60,
    };
    let scorer = ComplexityScorer::from_config(&config);
    assert_eq!(scorer.classify(20), "optimal");
    assert_eq!(scorer.classify(50), "complex");
    assert_eq!(scorer.classify(80), "critical");
}

#[test]
fn config_default_proven_mode() {
    let config = Config::default();
    assert_eq!(config.analysis.min_confidence, "proven");
}

#[test]
fn config_custom_rules_none_by_default() {
    let config = Config::default();
    assert!(config.analysis.custom_rules.is_none());
}

#[test]
fn config_complexity_defaults() {
    let config = Config::default();
    // Default derives give 0, serde defaults give 40/70
    assert!(!config.complexity.enabled);
    assert_eq!(config.complexity.threshold_optimal, 0);
    assert_eq!(config.complexity.threshold_complex, 0);
}
