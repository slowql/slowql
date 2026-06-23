use std::sync::{Mutex, OnceLock};

static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_cwd<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let _guard = CWD_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();
    let result = f();
    std::env::set_current_dir(original).unwrap();
    result
}

// Coverage tests for model types, display implementations,
// and template detection branches.

use slowql_lib::models::*;

use slowql_lib::models::query::Query;
use slowql_lib::models::result::AnalysisResult;

#[test]
fn severity_display_all() {
    assert_eq!(format!("{}", Severity::Critical), "critical");
    assert_eq!(format!("{}", Severity::High), "high");
    assert_eq!(format!("{}", Severity::Medium), "medium");
    assert_eq!(format!("{}", Severity::Low), "low");
    assert_eq!(format!("{}", Severity::Info), "info");
}

#[test]
fn dimension_display_all() {
    assert_eq!(format!("{}", Dimension::Security), "security");
    assert_eq!(format!("{}", Dimension::Performance), "performance");
    assert_eq!(format!("{}", Dimension::Reliability), "reliability");
    assert_eq!(format!("{}", Dimension::Compliance), "compliance");
    assert_eq!(format!("{}", Dimension::Cost), "cost");
    assert_eq!(format!("{}", Dimension::Quality), "quality");
    assert_eq!(format!("{}", Dimension::Schema), "schema");
    assert_eq!(Dimension::Data.as_str(), "data");
    assert_eq!(Dimension::Migration.as_str(), "migration");
    assert_eq!(Dimension::Operational.as_str(), "operational");
    assert_eq!(Dimension::Business.as_str(), "business");
}

#[test]
fn rule_confidence_display_all() {
    assert_eq!(format!("{}", RuleConfidence::Proven), "proven");
    assert_eq!(format!("{}", RuleConfidence::Contextual), "contextual");
    assert_eq!(format!("{}", RuleConfidence::Advisory), "advisory");
}

#[test]
fn fix_confidence_display_all() {
    assert_eq!(format!("{}", FixConfidence::Safe), "safe");
    assert_eq!(format!("{}", FixConfidence::Probable), "probable");
    assert_eq!(format!("{}", FixConfidence::Unsafe), "unsafe");
}

#[test]
fn remediation_mode_variants() {
    let _ = RemediationMode::SafeApply;
    let _ = RemediationMode::PreviewOnly;
    let _ = RemediationMode::GuidanceOnly;
}

#[test]
fn is_templated_curly_identifier() {
    let q = Query {
        raw: "SELECT * FROM {table_name} WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn is_templated_empty_curly() {
    let q = Query {
        raw: "SELECT {} FROM t".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn is_templated_underscore_curly() {
    let q = Query {
        raw: "SELECT {_col} FROM t".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn is_not_templated_begin_block() {
    let q = Query {
        raw: "DO $$ BEGIN RAISE NOTICE 'test'; END $$".to_string(),
        ..Default::default()
    };
    assert!(!q.is_templated());
}

#[test]
fn is_not_templated_jsonb_brace() {
    let q = Query {
        raw: "SELECT data FROM t WHERE JSONB_TYPEOF(data) = 'array'".to_string(),
        ..Default::default()
    };
    assert!(!q.is_templated());
}

#[test]
fn is_not_templated_curly_number() {
    let q = Query {
        raw: "SELECT * FROM t WHERE x = {1}".to_string(),
        ..Default::default()
    };
    assert!(!q.is_templated());
}

#[test]
fn is_update_check() {
    let q = Query { query_type: Some("UPDATE".to_string()), ..Default::default() };
    assert!(q.is_update());
    let q2 = Query { query_type: Some("SELECT".to_string()), ..Default::default() };
    assert!(!q2.is_update());
}

#[test]
fn config_serde_defaults() {
    use slowql_lib::config::Config;
    let config = Config::default();
    assert_eq!(config.severity.fail_on, "high");
    assert_eq!(config.output.format, "console");
    assert!(config.analysis.enabled_dimensions.contains("security"));
}

#[test]
fn config_find_and_load_yaml() {
    use slowql_lib::config::Config;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.yaml");
    std::fs::write(&path, "analysis:\n  dialect: mysql\n").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).ok();
    let config = Config::find_and_load();
    std::env::set_current_dir(original).ok();
    let _ = config;
}

#[test]
fn config_find_and_load_json() {
    use slowql_lib::config::Config;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.json");
    std::fs::write(&path, r#"{"analysis":{"dialect":"mysql"}}"#).unwrap();
    let config = with_cwd(dir.path(), Config::find_and_load);
    assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
}

#[test]
fn analysis_result_sorted() {
    let mut result = AnalysisResult::new();
    result.add_issue(Issue::new("A", "low", Severity::Low, Dimension::Quality, Location::new(1,1), "x"));
    result.add_issue(Issue::new("B", "high", Severity::High, Dimension::Security, Location::new(1,1), "x"));
    let sorted = result.sorted_by_severity();
    assert_eq!(sorted[0].severity, Severity::High);
}
