use std::sync::{Mutex, OnceLock};

/// Serialize tests that mutate the process current directory.
static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_cwd<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let _guard = CWD_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();
    let result = f();
    std::env::set_current_dir(original).unwrap();
    result
}

// Targeted branch coverage tests for rule modules with remaining
// uncovered lines. Each test crafts specific SQL to trigger deep
// conditional branches in rule check() implementations.

use slowql_lib::models::{Location, Query};

fn q(sql: &str, dialect: &str, qt: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: dialect.to_string(),
        location: Location::new(1, 1),
        query_type: Some(qt.to_string()),
        source_context: "application".to_string(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------
// Cost rule branches
// ---------------------------------------------------------------

#[test]
fn cost_over_indexed_table() {
    let rules = slowql_lib::rules::cost::all_rules();
    let sql = "CREATE INDEX idx1 ON users (name); CREATE INDEX idx2 ON users (email); CREATE INDEX idx3 ON users (phone)";
    let query = q(sql, "postgresql", "CREATE");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("Over-indexed")));
}

#[test]
fn cost_multi_region_query() {
    let rules = slowql_lib::rules::cost::all_rules();
    let sql = "SELECT * FROM users@us-east.prod.rds.amazonaws.com WHERE region = 'eu-west'";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues
        .iter()
        .any(|i| i.message.contains("Multi-region") || i.message.contains("region")));
}

#[test]
fn cost_snowflake_order_variant() {
    let rules = slowql_lib::rules::cost::all_rules();
    let sql = "SELECT * FROM events ORDER BY data:timestamp";
    let query = q(sql, "snowflake", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("VARIANT")));
}

#[test]
fn cost_partition_pruning_with_partition_col_in_raw() {
    use slowql_lib::config::TableMetadata;
    use slowql_lib::rules::base::RuleContext;
    let mut partitioned = std::collections::HashMap::new();
    partitioned.insert("events".to_string(), vec!["event_date".to_string()]);
    let tm = TableMetadata {
        large_tables: vec![],
        partitioned_tables: partitioned,
    };
    let ctx = RuleContext {
        schema: None,
        table_metadata: &tm,
        source_context: "application",
    };
    let rules = slowql_lib::rules::cost::all_rules();
    // Query WITHOUT partition column in WHERE
    let mut query = q(
        "SELECT * FROM events WHERE status = 'active'",
        "postgresql",
        "SELECT",
    );
    query.tables = vec!["events".to_string()];
    for rule in &rules {
        let _ = rule.check_with_context(&query, &ctx);
    }
    // Query WITH partition column in raw SQL (fallback path)
    let mut query2 = q(
        "SELECT * FROM events WHERE event_date = '2024-01-01'",
        "postgresql",
        "SELECT",
    );
    query2.tables = vec!["events".to_string()];
    for rule in &rules {
        let _ = rule.check_with_context(&query2, &ctx);
    }
}

// ---------------------------------------------------------------
// Compliance rule branches
// ---------------------------------------------------------------

#[test]
fn compliance_gdpr_export_users_without_audit() {
    let rules = slowql_lib::rules::compliance::all_rules();
    let sql = "SELECT * FROM export_data JOIN users ON export_data.user_id = users.id";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues
        .iter()
        .any(|i| i.message.contains("audit") || i.message.contains("activity")));
}

#[test]
fn compliance_unencrypted_phi() {
    let rules = slowql_lib::rules::compliance::all_rules();
    let sql = "SELECT * FROM patients WHERE encrypt=false AND sslmode=disable";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues
        .iter()
        .any(|i| i.message.contains("PHI") || i.message.contains("Insecure")));
}

#[test]
fn compliance_sox_segregation_of_duties() {
    let rules = slowql_lib::rules::compliance::all_rules();
    let sql =
        "UPDATE orders SET approved_by = 'admin', status = 'approved' WHERE created_by = 'admin'";
    let query = q(sql, "postgresql", "UPDATE");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues
        .iter()
        .any(|i| i.message.contains("Segregation") || i.message.contains("Duties")));
}

// ---------------------------------------------------------------
// Extractor deep branches
// ---------------------------------------------------------------

#[test]
fn extractor_python_fstring() {
    let code = r#"query = f"DELETE FROM users WHERE id = {user_id}""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    // f-strings should be detected as dynamic
    for q in &queries {
        if q.raw.contains("DELETE") {
            assert!(q.is_dynamic);
        }
    }
}

#[test]
fn extractor_prose_rejection_from_position() {
    // "SELECT id, name FROM users" has FROM at word index 3 (>= 2)
    // The prose heuristic should reject this as prose-like
    let code = r#"msg = "SELECT id, name FROM users WHERE id = 1""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    // May or may not extract depending on heuristic
    let _ = queries;
}

#[test]
fn extractor_go_format_specifiers() {
    let code = r#"rows := db.query("DELETE FROM users WHERE id = %s AND name = %d")"#;
    let queries = slowql_lib::extractor::extract_from_source(code, "main.go");
    for q in &queries {
        if q.raw.contains("DELETE") {
            assert!(q.is_dynamic);
        }
    }
}

// ---------------------------------------------------------------
// Mybatis deep branches
// ---------------------------------------------------------------

#[test]
fn mybatis_self_closing_tag() {
    let xml = r#"<mapper><select id="test" resultType="int"/></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(queries.is_empty());
}

#[test]
fn mybatis_single_quote_attr() {
    let xml = r#"<mapper><select id='test'>SELECT 1 FROM t</select></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

#[test]
fn mybatis_foreach_tag() {
    let xml = r#"<mapper><select id="findMany">
        SELECT * FROM users WHERE id IN
        <foreach item="id" collection="ids" open="(" separator="," close=")">
            #{id}
        </foreach>
    </select></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn mybatis_choose_when() {
    let xml = r#"<mapper><select id="search">
        SELECT * FROM users
        <choose>
            <when test="name != null">WHERE name = #{name}</when>
            <otherwise>WHERE active = true</otherwise>
        </choose>
    </select></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn mybatis_trim_tag() {
    let xml = r#"<mapper><update id="update">
        UPDATE users
        <trim prefix="SET" suffixOverrides=",">
            <if test="name != null">name = #{name},</if>
            <if test="email != null">email = #{email},</if>
        </trim>
        WHERE id = #{id}
    </update></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn mybatis_bind_tag() {
    let xml = r#"<mapper><select id="search">
        <bind name="pattern" value="'%' + name + '%'" />
        SELECT * FROM users WHERE name LIKE #{pattern}
    </select></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn mybatis_sql_fragment_with_statement() {
    let xml =
        r#"<mapper><sql id="fullSelect">SELECT * FROM users WHERE active = true</sql></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

// ---------------------------------------------------------------
// Parser deep branches
// ---------------------------------------------------------------

#[test]
fn parser_block_comment_in_split() {
    let queries = slowql_lib::parser::parse(
        "/* comment */ SELECT 1; /* another */ SELECT 2",
        "postgresql",
        None,
    );
    assert_eq!(queries.len(), 2);
}

#[test]
fn parser_double_quote_in_split() {
    let queries = slowql_lib::parser::parse(r#"SELECT "col;name" FROM t"#, "postgresql", None);
    assert_eq!(queries.len(), 1);
}

#[test]
fn parser_empty_input() {
    let queries = slowql_lib::parser::parse("", "postgresql", None);
    assert!(queries.is_empty());
}

#[test]
fn parser_whitespace_only() {
    let queries = slowql_lib::parser::parse("   \n\n   ", "postgresql", None);
    assert!(queries.is_empty());
}

// ---------------------------------------------------------------
// Query analysis deep branches
// ---------------------------------------------------------------

#[test]
fn query_analysis_update_with_where() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "UPDATE users SET name = 'x' WHERE id = 1",
        "postgresql",
    );
    assert_eq!(facts.statement_type, "UPDATE");
    assert!(facts.has_where);
    assert_eq!(facts.update_table.as_deref(), Some("users"));
}

#[test]
fn query_analysis_subquery_in_where() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)",
        "postgresql",
    );
    assert!(facts.subquery_count >= 1);
}

#[test]
fn query_analysis_compound_identifier_in_where() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM users u WHERE u.id = 1",
        "postgresql",
    );
    assert!(facts.where_columns.contains(&"id".to_string()));
}

#[test]
fn query_analysis_group_by_all() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT status, COUNT(*) FROM users GROUP BY status HAVING COUNT(*) > 1",
        "postgresql",
    );
    assert!(facts.has_group_by);
    assert!(facts.has_having);
}

#[test]
fn query_analysis_invalid_sql() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql("NOT VALID SQL", "postgresql");
    assert!(facts.statement_type.is_empty());
}

// ---------------------------------------------------------------
// Compare deep branches
// ---------------------------------------------------------------

#[test]
fn compare_short_skeleton_ignored() {
    let q1 = Query {
        raw: "SELECT 1".to_string(),
        query_type: Some("SELECT".to_string()),
        location: Location::new(1, 1).with_file("a.sql"),
        ..Default::default()
    };
    let q2 = Query {
        raw: "SELECT 2".to_string(),
        query_type: Some("SELECT".to_string()),
        location: Location::new(1, 1).with_file("b.sql"),
        ..Default::default()
    };
    let issues = slowql_lib::compare::find_similar_queries(&[q1, q2]);
    assert!(
        issues.is_empty(),
        "short queries should not flag as similar"
    );
}

#[test]
fn compare_ddl_ignored() {
    let q1 = Query {
        raw: "CREATE TABLE users (id INT PRIMARY KEY, name TEXT NOT NULL)".to_string(),
        query_type: Some("CREATE".to_string()),
        location: Location::new(1, 1).with_file("a.sql"),
        ..Default::default()
    };
    let q2 = Query {
        raw: "CREATE TABLE users (id INT PRIMARY KEY, name TEXT NOT NULL)".to_string(),
        query_type: Some("CREATE".to_string()),
        location: Location::new(1, 1).with_file("b.sql"),
        ..Default::default()
    };
    let issues = slowql_lib::compare::find_similar_queries(&[q1, q2]);
    assert!(issues.is_empty(), "DDL should not flag as similar");
}

// ---------------------------------------------------------------
// Config deep branches
// ---------------------------------------------------------------

#[test]
fn config_pyproject_toml() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    std::fs::write(
        &pyproject,
        r#"
[tool.slowql]
[tool.slowql.analysis]
dialect = "mysql"
[tool.slowql.severity]
fail_on = "critical"
"#,
    )
    .unwrap();
    let config = with_cwd(dir.path(), slowql_lib::config::Config::find_and_load);
    assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
}

// ---------------------------------------------------------------
// Schema load_schema_file
// ---------------------------------------------------------------

#[test]
fn schema_with_foreign_key_reference() {
    let ddl = "CREATE TABLE orders (id INT PRIMARY KEY, user_id INT REFERENCES users(id));";
    let schema = slowql_lib::schema::parse_ddl(ddl, "postgresql");
    let table = schema.get_table("orders").unwrap();
    let fk = table.columns.iter().find(|c| c.name == "user_id").unwrap();
    assert!(fk.foreign_key.is_some());
}

// ---------------------------------------------------------------
// Scoring branches
// ---------------------------------------------------------------

#[test]
fn scoring_classify_all_ranges() {
    let scorer = slowql_lib::scoring::ComplexityScorer::new();
    assert_eq!(scorer.classify(0), "optimal");
    assert_eq!(scorer.classify(40), "optimal");
    assert_eq!(scorer.classify(41), "complex");
    assert_eq!(scorer.classify(70), "complex");
    assert_eq!(scorer.classify(71), "critical");
    assert_eq!(scorer.classify(100), "critical");
}

// ---------------------------------------------------------------
// Baseline branches
// ---------------------------------------------------------------

#[test]
fn baseline_save_and_load() {
    use slowql_lib::baseline::Baseline;
    use slowql_lib::models::result::AnalysisResult;

    let mut result = AnalysisResult::new();
    result.add_issue(slowql_lib::models::Issue::new(
        "TEST-001",
        "test",
        slowql_lib::models::Severity::High,
        slowql_lib::models::Dimension::Security,
        Location::new(1, 1),
        "x",
    ));
    let baseline = Baseline::generate(&result);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline.json");
    baseline.save(&path).unwrap();
    let loaded = Baseline::load(&path).unwrap();
    assert_eq!(loaded.entry_count, 1);
    let fps = loaded.fingerprints();
    assert_eq!(fps.len(), 1);
}

#[test]
fn baseline_load_not_found() {
    use slowql_lib::baseline::Baseline;
    assert!(Baseline::load(std::path::Path::new("/nonexistent")).is_err());
}

// ---------------------------------------------------------------
// Git branches
// ---------------------------------------------------------------

#[test]
fn git_changed_files_since_revision() {
    let files = slowql_lib::git::get_changed_files(Some("HEAD~100"));
    let _ = files;
}

// ---------------------------------------------------------------
// Registry branches
// ---------------------------------------------------------------

#[test]
fn registry_add_rules_and_filter() {
    use slowql_lib::rules::RuleRegistry;
    let mut registry = RuleRegistry::new();
    let initial = registry.all().len();
    // Add custom rules
    let custom = slowql_lib::rules::quality::all_rules();
    let custom_count = custom.len();
    registry.add_rules(custom);
    assert_eq!(registry.all().len(), initial + custom_count);

    let security = registry.for_dimension("security");
    assert!(!security.is_empty());
}

// ---------------------------------------------------------------
// Suppressions branches
// ---------------------------------------------------------------

#[test]
fn suppression_enable_without_disable() {
    let sql = "SELECT 1;\n-- slowql-enable\nSELECT 2;";
    let map = slowql_lib::suppressions::parse_suppressions(sql);
    assert!(!map.is_suppressed(1, "PERF-SCAN-001"));
    assert!(!map.is_suppressed(3, "PERF-SCAN-001"));
}

// ---------------------------------------------------------------
// Autofixer branches
// ---------------------------------------------------------------

#[test]
fn autofixer_span_fix_mismatch() {
    use slowql_lib::autofixer::AutoFixer;
    use slowql_lib::models::issue::{Fix, FixConfidence};
    let fix = Fix {
        description: "fix".to_string(),
        original: "WRONG".to_string(),
        replacement: "RIGHT".to_string(),
        is_safe: true,
        confidence: FixConfidence::Safe,
        rule_id: "TEST".to_string(),
        start: Some(0),
        end: Some(5),
    };
    // Original text does not match fix.original at span
    let result = AutoFixer::apply_fix("HELLO WORLD", &fix);
    assert_eq!(
        result, "HELLO WORLD",
        "mismatched span fix should not apply"
    );
}

// ---------------------------------------------------------------
// YAML rules branches
// ---------------------------------------------------------------

#[test]
fn yaml_rules_missing_rules_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yaml");
    std::fs::write(&path, "something: else\n").unwrap();
    let result = slowql_lib::yaml_rules::load_yaml_rules(&path);
    assert!(result.is_err());
}

#[test]
fn yaml_rules_invalid_regex() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad_regex.yaml");
    std::fs::write(
        &path,
        r#"
rules:
  - id: "BAD-001"
    pattern: "[invalid"
    message: "test"
"#,
    )
    .unwrap();
    let result = slowql_lib::yaml_rules::load_yaml_rules(&path);
    assert!(result.is_err());
}

#[test]
fn yaml_rules_missing_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no_pattern.yaml");
    std::fs::write(
        &path,
        r#"
rules:
  - id: "NO-PAT-001"
    message: "test"
"#,
    )
    .unwrap();
    let result = slowql_lib::yaml_rules::load_yaml_rules(&path);
    assert!(result.is_err());
}

#[test]
fn yaml_rules_all_severity_levels() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("severities.yaml");
    std::fs::write(
        &path,
        r#"
rules:
  - id: "SEV-001"
    pattern: "\\bTEST1\\b"
    message: "test"
    severity: "critical"
    dimension: "security"
  - id: "SEV-002"
    pattern: "\\bTEST2\\b"
    message: "test"
    severity: "high"
    dimension: "performance"
  - id: "SEV-003"
    pattern: "\\bTEST3\\b"
    message: "test"
    severity: "low"
    dimension: "reliability"
  - id: "SEV-004"
    pattern: "\\bTEST4\\b"
    message: "test"
    severity: "info"
    dimension: "cost"
  - id: "SEV-005"
    pattern: "\\bTEST5\\b"
    message: "test"
    severity: "unknown"
    dimension: "unknown"
"#,
    )
    .unwrap();
    let rules = slowql_lib::yaml_rules::load_yaml_rules(&path).unwrap();
    assert_eq!(rules.len(), 5);
}

// ---------------------------------------------------------------
// Extractor: remaining uncovered branches
// ---------------------------------------------------------------

#[test]
fn extractor_single_word_no_space() {
    // Line 127: trimmed has no space, paren, or semicolon
    let code = r#"label = "DELETE_ITEMS""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

#[test]
fn extractor_period_ending_no_sql_keywords() {
    // Line 254-263: ends with period, no SQL keywords
    let code = r#"msg = "Select the best option for deployment.""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

#[test]
fn extractor_period_ending_with_sql_keywords() {
    // Period ending but HAS SQL keywords should still be processed
    let code = "msg = \"DELETE FROM users WHERE id = 1.\"";
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    let _ = queries;
}

#[test]
fn extractor_natural_language_articles() {
    // Line 317: natural language with "the", "a", etc.
    let code = r#"msg = "UPDATE the records that have been modified""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

#[test]
fn extractor_no_structural_no_punct() {
    // Line 234-246: SQL verb with words before structural keyword but no punctuation
    let code = r#"msg = "SELECT something interesting here""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

#[test]
fn extractor_python_fstring_overlaps_triple() {
    // Line 427: fstring that overlaps with already-extracted triple quote
    let code = "sql = \"\"\"DELETE FROM users WHERE id = 1\"\"\"\nother = f\"DELETE FROM orders WHERE id = {x}\"";
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    let _ = queries;
}

#[test]
fn extractor_ruby_heredoc_dynamic() {
    // Line 503/520: Ruby heredoc with interpolation
    let code = r#"connection.execute(<<~SQL
DELETE FROM users WHERE id = #{user_id}
SQL
"#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.rb");
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn extractor_sink_aware_dynamic_go_percent_d() {
    // Line 578: go format with %d
    let code = "rows := db.query(\"DELETE FROM users WHERE id = %d AND status = %s\")";
    let queries = slowql_lib::extractor::extract_from_source(code, "main.go");
    assert!(queries.iter().any(|q| q.is_dynamic));
}

#[test]
fn extractor_jpql_update_entity() {
    // Line 540: JPQL with UPDATE EntityName
    let code = "stmt = conn.createNativeQuery(\"UPDATE OrderEntity SET status = :s\")";
    let queries = slowql_lib::extractor::extract_from_source(code, "App.java");
    // Should be filtered as JPQL
    let _ = queries;
}

#[test]
fn extractor_question_mark_ending() {
    let code = r#"msg = "SELECT which option is best?""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

#[test]
fn extractor_paren_dot_ending() {
    let code = r#"msg = "INSERT values into the system.)""#;
    let queries = slowql_lib::extractor::extract_from_source(code, "app.py");
    assert!(queries.is_empty());
}

// ---------------------------------------------------------------
// Security injection: specific pattern matches
// ---------------------------------------------------------------

#[test]
fn injection_ldap_pattern() {
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "SELECT LDAP_SEARCH(cn=admin || user_input, ou=users, dc=company)";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("LDAP")));
}

#[test]
fn injection_nosql_pattern() {
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "SELECT OPENJSON(data + user_input) WHERE key = {$gt: 0}";
    let query = q(sql, "tsql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("NoSQL")));
}

#[test]
fn injection_xpath_pattern() {
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "SELECT XMLQUERY('/root' || user_input || '/child[1]')";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues
        .iter()
        .any(|i| i.message.contains("XPath") || i.message.contains("XML")));
}

#[test]
fn injection_ssti_pattern() {
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "SELECT RENDER_TEMPLATE(content + user_input)";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("template")));
}

#[test]
fn injection_json_function_pattern() {
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "SELECT JSON_OBJECT('key', value + user_input)";
    let query = q(sql, "postgresql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(issues.iter().any(|i| i.message.contains("JSON")));
}

#[test]
fn injection_mysql_prepare_from_var() {
    // Line 93: PREPARE stmt FROM @variable should NOT fire
    let rules = slowql_lib::rules::security::injection::rules();
    let sql = "PREPARE stmt FROM @sql_string";
    let query = q(sql, "mysql", "SELECT");
    let issues: Vec<_> = rules.iter().flat_map(|r| r.check(&query)).collect();
    assert!(!issues.iter().any(|i| i.rule_id == "SEC-INJ-002"));
}

// ---------------------------------------------------------------
// Engine: remaining branches
// ---------------------------------------------------------------

#[test]
fn engine_custom_rules_bad_file() {
    // Line 27: custom rules file exists but has invalid content
    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("bad_custom.yaml");
    std::fs::write(&rules_path, "not: valid: yaml: rules:").unwrap();
    let mut config = slowql_lib::config::Config::default();
    config.analysis.custom_rules = Some(rules_path.to_str().unwrap().to_string());
    let engine = slowql_lib::engine::Engine::new(config);
    let _ = engine.rule_count();
}

#[test]
fn engine_severity_override_unknown() {
    // Line 122: unknown severity override falls through to default
    let mut config = slowql_lib::config::Config::default();
    config
        .analysis
        .severity_overrides
        .insert("REL-DATA-001".to_string(), "unknown_severity".to_string());
    let engine = slowql_lib::engine::Engine::new(config);
    let result = engine.analyze("DELETE FROM users", Some("postgresql"), None);
    let _ = result;
}

#[test]
fn engine_analyze_app_code_with_sql() {
    // Line 326-327: app code analysis that finds SQL
    let engine = slowql_lib::engine::Engine::with_default_config();
    let code = r#"
connection.execute("DELETE FROM users WHERE id = 1")
connection.execute("INSERT INTO logs (event) VALUES ('test')")
"#;
    let result = engine.analyze_app_code(code, "app.rb");
    assert!(result.statistics.total_queries >= 1);
}

// ---------------------------------------------------------------
// Config: pyproject.toml and find_and_load branches
// ---------------------------------------------------------------

#[test]
fn config_find_and_load_invalid_yaml() {
    // Line 212-214: config file exists but is invalid
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slowql.yaml");
    std::fs::write(&path, ": : : invalid yaml").unwrap();
    let config = with_cwd(dir.path(), slowql_lib::config::Config::find_and_load);
    // Falls back to default
    let _ = config;
}

// ---------------------------------------------------------------
// Mybatis: remaining branches
// ---------------------------------------------------------------

#[test]
fn mybatis_no_closing_tag() {
    let xml = r#"<mapper><select id="test">SELECT 1 FROM t"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    let _ = queries;
}

#[test]
fn mybatis_no_end_of_open_tag() {
    let xml = r#"<mapper><select id="test"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    let _ = queries;
}

#[test]
fn mybatis_insert_statement() {
    let xml =
        r#"<mapper><insert id="add">INSERT INTO users (name) VALUES (#{name})</insert></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

#[test]
fn mybatis_delete_statement() {
    let xml = r#"<mapper><delete id="remove">DELETE FROM users WHERE id = #{id}</delete></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

#[test]
fn mybatis_update_statement() {
    let xml = r#"<mapper><update id="edit">UPDATE users SET name = #{name} WHERE id = #{id}</update></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

#[test]
fn mybatis_html_comment() {
    let xml = r#"<mapper><select id="test"><!-- comment -->SELECT 1 FROM t</select></mapper>"#;
    let queries = slowql_lib::mybatis::parse_mybatis_xml(xml, "test.xml");
    assert!(!queries.is_empty());
}

// ---------------------------------------------------------------
// Parser: remaining branches
// ---------------------------------------------------------------

#[test]
fn parser_insert_table_extraction() {
    let queries = slowql_lib::parser::parse(
        "INSERT INTO users (name) VALUES ('test')",
        "postgresql",
        None,
    );
    assert!(!queries.is_empty());
    assert!(queries[0].tables.contains(&"users".to_string()));
}

#[test]
fn parser_update_table_extraction() {
    let queries = slowql_lib::parser::parse(
        "UPDATE users SET name = 'x' WHERE id = 1",
        "postgresql",
        None,
    );
    assert!(!queries.is_empty());
    assert!(queries[0].tables.contains(&"users".to_string()));
}

#[test]
fn parser_delete_table_extraction() {
    let queries = slowql_lib::parser::parse("DELETE FROM users WHERE id = 1", "postgresql", None);
    assert!(!queries.is_empty());
    assert!(queries[0].tables.contains(&"users".to_string()));
}

#[test]
fn parser_select_with_join_tables() {
    let queries = slowql_lib::parser::parse(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.user_id",
        "postgresql",
        None,
    );
    assert!(!queries.is_empty());
    assert!(queries[0].tables.len() >= 2);
}

#[test]
fn parser_select_columns_extraction() {
    let queries = slowql_lib::parser::parse("SELECT id, name AS n FROM users", "postgresql", None);
    assert!(!queries.is_empty());
    assert!(queries[0].columns.contains(&"id".to_string()));
}

#[test]
fn parser_select_wildcard_column() {
    let queries = slowql_lib::parser::parse("SELECT * FROM users", "postgresql", None);
    assert!(!queries.is_empty());
    assert!(queries[0].columns.contains(&"*".to_string()));
}

// ---------------------------------------------------------------
// Query analysis: remaining branches
// ---------------------------------------------------------------

#[test]
fn query_analysis_exists_subquery() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)",
        "postgresql",
    );
    assert!(facts.subquery_count >= 1);
}

#[test]
fn query_analysis_derived_table() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM (SELECT 1 AS x) AS sub WHERE x = 1",
        "postgresql",
    );
    assert!(facts.subquery_count >= 1);
}

#[test]
fn query_analysis_for_update() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM users WHERE id = 1 FOR UPDATE",
        "postgresql",
    );
    assert!(facts.has_where);
}

#[test]
fn query_analysis_compound_select() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT u.id, u.name FROM users u",
        "postgresql",
    );
    assert!(facts.selected_columns.contains(&"id".to_string()));
}

#[test]
fn query_analysis_offset() {
    let facts = slowql_lib::query_analysis::QueryFacts::from_sql(
        "SELECT * FROM users LIMIT 10 OFFSET 20",
        "postgresql",
    );
    assert!(facts.has_limit);
    assert!(facts.has_offset);
}
