use slowql_lib::models::{AnalysisResult, Dimension, Issue, Location, Severity};

#[test]
fn severity_order_is_correct() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn issue_creation_sets_fields() {
    let issue = Issue::new(
        "SEC-INJ-001",
        "test message",
        Severity::Critical,
        Dimension::Security,
        Location::new(1, 1),
        "SELECT *",
    );

    assert_eq!(issue.rule_id, "SEC-INJ-001");
    assert_eq!(issue.message, "test message");
    assert_eq!(issue.severity, Severity::Critical);
    assert_eq!(issue.dimension, Dimension::Security);
    assert_eq!(issue.location.line, 1);
    assert_eq!(issue.location.column, 1);
    assert_eq!(issue.snippet, "SELECT *");
}

#[test]
fn analysis_result_exit_codes_match_current_python_behavior() {
    let mut result = AnalysisResult::new();
    assert_eq!(result.exit_code(), 0);

    result.add_issue(Issue::new(
        "TEST-INFO-001",
        "info",
        Severity::Info,
        Dimension::Quality,
        Location::new(1, 1),
        "x",
    ));
    assert_eq!(result.exit_code(), 0);

    result.add_issue(Issue::new(
        "TEST-LOW-001",
        "low",
        Severity::Low,
        Dimension::Quality,
        Location::new(1, 1),
        "x",
    ));
    assert_eq!(result.exit_code(), 1);

    let mut high = AnalysisResult::new();
    high.add_issue(Issue::new(
        "TEST-HIGH-001",
        "high",
        Severity::High,
        Dimension::Security,
        Location::new(1, 1),
        "x",
    ));
    assert_eq!(high.exit_code(), 2);

    let mut critical = AnalysisResult::new();
    critical.add_issue(Issue::new(
        "TEST-CRIT-001",
        "crit",
        Severity::Critical,
        Dimension::Security,
        Location::new(1, 1),
        "x",
    ));
    assert_eq!(critical.exit_code(), 3);
}
