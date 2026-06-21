use slowql_lib::models::{Location, Query};
use slowql_lib::rules::quality;
use slowql_lib::rules::Rule;
fn q(sql: &str, dialect: &str, qt: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: dialect.to_string(),
        location: Location::new(1, 1),
        start_offset: None,
        end_offset: None,
        tables: vec![],
        columns: vec![],
        query_type: Some(qt.to_string()),
        is_ddl: false,
        is_dynamic: false,
        complexity_score: 0,
        source_context: "application".to_string(),
        ..Default::default()
    }
}
fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule {
    rules
        .iter()
        .find(|r| r.id() == id)
        .map(|r| r.as_ref())
        .unwrap_or_else(|| panic!("rule {} not found", id))
}
fn all() -> Vec<Box<dyn Rule>> {
    quality::all_rules()
}

#[test]
fn quality_rule_count() {
    assert_eq!(all().len(), 51);
}
#[test]
fn null_001() {
    let r = all();
    let rule = find(&r, "QUAL-NULL-001");
    assert!(!rule
        .check(&q("SELECT * FROM t WHERE x = NULL", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE x IS NULL",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn style_002() {
    let r = all();
    let rule = find(&r, "QUAL-STYLE-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t WHERE EXISTS (SELECT * FROM s)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM s)",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn modern_003() {
    let r = all();
    let rule = find(&r, "QUAL-MODERN-003");
    assert!(!rule
        .check(&q("SELECT 1 UNION SELECT 2", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT 1 UNION ALL SELECT 2", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn modern_004() {
    let r = all();
    let rule = find(&r, "QUAL-MODERN-004");
    assert!(!rule
        .check(&q(
            "SELECT CASE WHEN x=1 THEN 'a' END FROM t",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT CASE WHEN x=1 THEN 'a' ELSE 'b' END FROM t",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn style_005() {
    let r = all();
    let rule = find(&r, "QUAL-STYLE-005");
    assert!(!rule
        .check(&q("INSERT INTO t VALUES (1,2,3)", "postgresql", "INSERT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "INSERT INTO t (a,b,c) VALUES (1,2,3)",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
}
#[test]
fn schema_001() {
    let r = all();
    let rule = find(&r, "QUAL-SCHEMA-001");
    assert!(!rule
        .check(&q("CREATE TABLE t (id INT)", "postgresql", "CREATE"))
        .is_empty());
    assert!(rule
        .check(&q(
            "CREATE TABLE t (id INT PRIMARY KEY)",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
}
#[test]
fn schema_004() {
    let r = all();
    let rule = find(&r, "QUAL-SCHEMA-004");
    assert!(!rule
        .check(&q("CREATE TABLE t (price FLOAT)", "postgresql", "CREATE"))
        .is_empty());
    assert!(rule
        .check(&q(
            "CREATE TABLE t (price DECIMAL(10,2))",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
}
#[test]
fn test_001() {
    let r = all();
    let rule = find(&r, "QUAL-TEST-001");
    assert!(!rule
        .check(&q("SELECT NOW() FROM t", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT id FROM t", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn test_002() {
    let r = all();
    let rule = find(&r, "QUAL-TEST-002");
    assert!(!rule
        .check(&q(
            "SELECT * FROM t LIMIT 10 OFFSET 0",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t ORDER BY id LIMIT 10",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn debt_001() {
    let r = all();
    let rule = find(&r, "QUAL-DEBT-001");
    assert!(!rule
        .check(&q("SELECT 1 -- TODO fix this", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT 1", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn tsql_001() {
    let r = all();
    let rule = find(&r, "QUAL-TSQL-001");
    assert!(!rule
        .check(&q("SET ANSI_NULLS OFF", "tsql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SET ANSI_NULLS OFF", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn ora_001() {
    let r = all();
    let rule = find(&r, "QUAL-ORA-001");
    assert!(!rule
        .check(&q("SELECT * FROM t WHERE ROWNUM <= 10", "oracle", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY id",
            "oracle",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM t WHERE ROWNUM <= 10", "mysql", "SELECT"))
        .is_empty());
}
#[test]
fn pg_001() {
    let r = all();
    let rule = find(&r, "QUAL-PG-001");
    assert!(!rule
        .check(&q(
            "DO $$ BEGIN RAISE NOTICE 'hi'; END $$;",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "DO $$ BEGIN END $$ LANGUAGE plpgsql;",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("DO $$ BEGIN END $$;", "mysql", "SELECT"))
        .is_empty());
}

// --- QUAL-DOC-002 precision tests ---

#[test]
fn doc_002_email_literal_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    // Email address in WHERE is not a magic constant
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE email = 'john@example.com'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

#[test]
fn doc_002_common_status_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    // Common self-documenting enum values should not fire
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE status = 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT id FROM orders WHERE status = 'pending'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

#[test]
fn doc_002_non_classification_column_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    // Columns that are not business classification fields should not fire
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE name = 'john'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE email = 'test@test.com'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

#[test]
fn doc_002_adhoc_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    let mut query = q(
        "SELECT id FROM users WHERE status = 'obscure_value_xyz'",
        "postgresql",
        "SELECT",
    );
    query.source_context = "adhoc".to_string();
    assert!(rule.check(&query).is_empty());
}

#[test]
fn doc_002_commented_query_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    // Query with comment should not fire
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE status = 'obscure_value' -- business rule",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}

#[test]
fn doc_002_dynamic_sql_no_fire() {
    let r = all();
    let rule = find(&r, "QUAL-DOC-002");
    // Dynamic SQL should not fire (injection is the real problem)
    assert!(rule
        .check(&q(
            "SELECT id FROM users WHERE status = 'x' || input_var",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
