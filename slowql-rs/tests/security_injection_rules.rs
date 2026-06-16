use slowql_lib::models::{Location, Query};
use slowql_lib::rules::security::injection::rules as injection_rules;
use slowql_lib::rules::Rule;

fn query(sql: &str, dialect: &str, query_type: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: dialect.to_string(),
        location: Location::new(1, 1),
        start_offset: None,
        end_offset: None,
        tables: vec![],
        columns: vec![],
        query_type: Some(query_type.to_string()),
        is_ddl: false,
        is_dynamic: false,
        complexity_score: 0,
        source_context: String::new(), ..Default::default()
    }
}

fn find_rule<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule {
    rules.iter().find(|r| r.id() == id).map(|r| r.as_ref()).unwrap()
}

#[test]
fn sec_inj_001_detects_string_concatenation() {
    let rules = injection_rules();
    let rule = find_rule(&rules, "SEC-INJ-001");
    let q = query("SELECT * FROM users WHERE name = 'x' + user_input", "postgresql", "SELECT");
    let issues = rule.check(&q);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].rule_id, "SEC-INJ-001");
}

#[test]
fn sec_inj_002_detects_dynamic_sql_execution() {
    let rules = injection_rules();
    let rule = find_rule(&rules, "SEC-INJ-002");
    let q = query("EXECUTE IMMEDIATE sql_stmt", "oracle", "SELECT");
    let issues = rule.check(&q);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].rule_id, "SEC-INJ-002");
}

#[test]
fn sec_inj_003_detects_or_1_equals_1() {
    let rules = injection_rules();
    let rule = find_rule(&rules, "SEC-INJ-003");
    let q = query("SELECT * FROM users WHERE id = 1 OR 1=1", "postgresql", "SELECT");
    let issues = rule.check(&q);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].rule_id, "SEC-INJ-003");
}

#[test]
fn sec_inj_004_detects_sleep() {
    let rules = injection_rules();
    let rule = find_rule(&rules, "SEC-INJ-004");
    let q = query("SELECT pg_sleep(5)", "postgresql", "SELECT");
    let issues = rule.check(&q);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].rule_id, "SEC-INJ-004");
}

#[test]
fn sec_pg_003_respects_dialect() {
    let rules = injection_rules();
    let rule = find_rule(&rules, "SEC-PG-003");

    let pg = query("RAISE NOTICE 'x' || user_name", "postgresql", "SELECT");
    assert_eq!(rule.check(&pg).len(), 1);

    let mysql = query("RAISE NOTICE 'x' || user_name", "mysql", "SELECT");
    assert_eq!(rule.check(&mysql).len(), 0);
}
