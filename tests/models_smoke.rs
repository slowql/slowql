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

#[test]
fn severity_display_and_parse() {
    for sev in &["critical", "high", "medium", "low", "info"] {
        let parsed: Severity = sev.parse().unwrap();
        assert_eq!(parsed.as_str(), *sev);
    }
    assert!("invalid".parse::<Severity>().is_err());
}

#[test]
fn severity_weight() {
    assert!(Severity::Critical.weight() > Severity::High.weight());
    assert!(Severity::High.weight() > Severity::Medium.weight());
    assert!(Severity::Medium.weight() > Severity::Low.weight());
    assert!(Severity::Low.weight() > Severity::Info.weight());
}

#[test]
fn severity_color_codes() {
    assert!(!Severity::Critical.color_code().is_empty());
    assert!(!Severity::High.color_code().is_empty());
    assert!(!Severity::Medium.color_code().is_empty());
    assert!(!Severity::Low.color_code().is_empty());
    assert!(!Severity::Info.color_code().is_empty());
}

#[test]
fn dimension_display_and_parse() {
    for dim in &[
        "security",
        "performance",
        "reliability",
        "compliance",
        "cost",
        "quality",
    ] {
        let parsed: Dimension = dim.parse().unwrap();
        assert_eq!(parsed.as_str(), *dim);
    }
    assert!("invalid".parse::<Dimension>().is_err());
}

#[test]
fn issue_with_methods() {
    let issue = Issue::new(
        "TEST-001",
        "test",
        Severity::High,
        Dimension::Security,
        Location::new(1, 1),
        "snip",
    )
    .with_category(slowql_lib::models::issue::Category::SecInjection)
    .with_impact("bad things happen")
    .with_tags(vec!["tag1".to_string()]);
    assert_eq!(
        issue.category,
        Some(slowql_lib::models::issue::Category::SecInjection)
    );
    assert_eq!(issue.impact.as_deref(), Some("bad things happen"));
    assert_eq!(issue.tags, vec!["tag1".to_string()]);
}

#[test]
fn issue_with_fix() {
    let fix = slowql_lib::models::Fix::safe("fix it", "= NULL", "IS NULL", "TEST-001");
    assert!(fix.is_safe);
    let issue = Issue::new(
        "TEST-001",
        "test",
        Severity::High,
        Dimension::Quality,
        Location::new(1, 1),
        "snip",
    )
    .with_fix(fix);
    assert!(issue.fix.is_some());
    assert!(issue.fix.unwrap().is_safe);
}

#[test]
fn location_display() {
    let loc = Location::new(10, 5);
    assert_eq!(format!("{}", loc), "10:5");
    let loc_file = Location::new(10, 5).with_file("test.sql");
    assert_eq!(format!("{}", loc_file), "test.sql:10:5");
}

#[test]
fn result_exit_code_no_issues() {
    let result = AnalysisResult::new();
    assert_eq!(result.exit_code(), 0);
}

#[test]
fn result_sorted_by_severity() {
    let mut result = AnalysisResult::new();
    result.add_issue(Issue::new(
        "A",
        "low",
        Severity::Low,
        Dimension::Quality,
        Location::new(1, 1),
        "x",
    ));
    result.add_issue(Issue::new(
        "B",
        "critical",
        Severity::Critical,
        Dimension::Security,
        Location::new(2, 1),
        "x",
    ));
    result.add_issue(Issue::new(
        "C",
        "medium",
        Severity::Medium,
        Dimension::Performance,
        Location::new(3, 1),
        "x",
    ));
    let sorted = result.sorted_by_severity();
    assert_eq!(sorted[0].rule_id, "B");
    assert_eq!(sorted[1].rule_id, "C");
    assert_eq!(sorted[2].rule_id, "A");
}

#[test]
fn rule_confidence_parse() {
    assert_eq!(
        "proven"
            .parse::<slowql_lib::models::issue::RuleConfidence>()
            .unwrap(),
        slowql_lib::models::issue::RuleConfidence::Proven
    );
    assert_eq!(
        "contextual"
            .parse::<slowql_lib::models::issue::RuleConfidence>()
            .unwrap(),
        slowql_lib::models::issue::RuleConfidence::Contextual
    );
    assert_eq!(
        "advisory"
            .parse::<slowql_lib::models::issue::RuleConfidence>()
            .unwrap(),
        slowql_lib::models::issue::RuleConfidence::Advisory
    );
    assert!("invalid"
        .parse::<slowql_lib::models::issue::RuleConfidence>()
        .is_err());
}

#[test]
fn query_is_select() {
    let q = slowql_lib::models::Query {
        query_type: Some("SELECT".to_string()),
        ..Default::default()
    };
    assert!(q.is_select());
    assert!(!q.is_insert());
    assert!(!q.is_update());
    assert!(!q.is_delete());
}

#[test]
fn query_is_insert() {
    let q = slowql_lib::models::Query {
        query_type: Some("INSERT".to_string()),
        ..Default::default()
    };
    assert!(q.is_insert());
    assert!(!q.is_select());
}

#[test]
fn query_raw_upper_cached() {
    let q = slowql_lib::models::Query {
        raw: "select * from users".to_string(),
        ..Default::default()
    };
    assert_eq!(q.raw_upper(), "SELECT * FROM USERS");
    // Second call uses cache
    assert_eq!(q.raw_upper(), "SELECT * FROM USERS");
}

#[test]
fn query_raw_lower_cached() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM Users".to_string(),
        ..Default::default()
    };
    assert_eq!(q.raw_lower(), "select * from users");
}

#[test]
fn query_has_keyword() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM users WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert!(q.has_keyword("WHERE"));
    assert!(q.has_keyword("from"));
    assert!(!q.has_keyword("JOIN"));
}

#[test]
fn query_snippet() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM users WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert_eq!(q.snippet(10), "SELECT * F");
    assert_eq!(q.snippet(1000), "SELECT * FROM users WHERE id = 1");
}

#[test]
fn query_snippet_respects_utf8_boundaries() {
    let raw = "SELECT fidèle ORDER BY id";
    let q = slowql_lib::models::Query {
        raw: raw.to_string(),
        ..Default::default()
    };

    let (multibyte_start, multibyte_char) = raw
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii())
        .expect("expected multibyte character");
    let inside_multibyte = multibyte_start + 1;
    let after_multibyte = multibyte_start + multibyte_char.len_utf8();

    assert!(multibyte_char.len_utf8() > 1);
    assert_eq!(q.snippet(inside_multibyte), &raw[..multibyte_start]);
    assert_eq!(q.snippet(after_multibyte), &raw[..after_multibyte]);
}

#[test]
fn query_is_templated_python() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM %s WHERE id = %s".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn query_is_templated_ruby() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM #{table} WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn query_is_templated_go() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM {{ .Ident .Table }} WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert!(q.is_templated());
}

#[test]
fn query_not_templated() {
    let q = slowql_lib::models::Query {
        raw: "SELECT * FROM users WHERE id = 1".to_string(),
        ..Default::default()
    };
    assert!(!q.is_templated());
}
