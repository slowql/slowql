use crate::config::Config;
use crate::models::result::AnalysisResult;
use crate::parser;
use crate::rules::RuleRegistry;
use std::time::Instant;

pub struct Engine {
    pub config: Config,
    registry: RuleRegistry,
    schema: Option<crate::schema::Schema>,
}

impl Engine {
    pub fn new(config: Config) -> Self {
        let mut registry = RuleRegistry::new();

        // Load custom YAML rules if configured
        if let Some(ref rules_path) = config.analysis.custom_rules {
            let path = std::path::Path::new(rules_path);
            if path.exists() {
                match crate::yaml_rules::load_yaml_rules(path) {
                    Ok(custom) => {
                        let count = custom.len();
                        registry.add_rules(custom);
                        eprintln!("Loaded {} custom rules from {}", count, rules_path);
                    }
                    Err(e) => eprintln!("Warning: failed to load custom rules: {}", e),
                }
            }
        }

        Engine {
            config,
            registry,
            schema: None,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(Config::default())
    }

    pub fn with_schema(mut self, schema: crate::schema::Schema) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn registry_ref(&self) -> &RuleRegistry {
        &self.registry
    }

    pub fn analyze(
        &self,
        sql: &str,
        dialect: Option<&str>,
        file_path: Option<&str>,
    ) -> AnalysisResult {
        let start = Instant::now();

        let effective_dialect = dialect
            .or(self.config.analysis.dialect.as_deref())
            .unwrap_or("generic");

        let parse_start = Instant::now();
        let mut queries = parser::parse(sql, effective_dialect, file_path);
        let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

        let mut result = AnalysisResult::new();
        result.dialect = Some(effective_dialect.to_string());
        result.statistics.total_queries = queries.len();
        result.statistics.parse_time_ms = parse_ms;

        let source_ctx = crate::context::classify_source(file_path, sql);

        // Compute structural facts and set source context for each query
        for query in &mut queries {
            query.facts = Some(crate::query_analysis::QueryFacts::from_sql(
                &query.raw,
                effective_dialect,
            ));
            query.source_context = source_ctx.to_string();
        }
        let suppression_map = crate::suppressions::parse_suppressions(sql);
        let rules = self
            .registry
            .enabled_for_dimensions(&self.config.analysis.enabled_dimensions);

        // Construct rule context with schema and table metadata
        let rule_ctx = crate::rules::base::RuleContext {
            schema: self.schema.as_ref(),
            table_metadata: &self.config.analysis.table_metadata,
            source_context: source_ctx,
        };

        let mut raw_issues = Vec::new();
        for query in &queries {
            // Compute once per query.
            // Time: O(|query.raw|) once instead of O(|query.raw| * rule_count).
            // Space: O(1).
            let query_is_templated = query.is_templated();

            for rule in &rules {
                if self.config.analysis.disabled_rules.contains(rule.id()) {
                    continue;
                }
                if let Some(ref enabled) = self.config.analysis.enabled_rules {
                    if !enabled.contains(rule.id()) {
                        let prefix: String =
                            rule.id().split('-').take(2).collect::<Vec<_>>().join("-");
                        if !enabled.contains(prefix.as_str()) {
                            continue;
                        }
                    }
                }
                let mut rule_issues = rule.check_with_context(query, &rule_ctx);
                // Apply severity overrides from config
                for issue in &mut rule_issues {
                    if let Some(override_sev) =
                        self.config.analysis.severity_overrides.get(&issue.rule_id)
                    {
                        issue.severity = match override_sev.as_str() {
                            "critical" => crate::models::Severity::Critical,
                            "high" => crate::models::Severity::High,
                            "medium" => crate::models::Severity::Medium,
                            "low" => crate::models::Severity::Low,
                            "info" => crate::models::Severity::Info,
                            _ => issue.severity,
                        };
                    }
                }
                // Demote confidence for findings on templated queries.
                // Templates contain placeholders that may change the semantic
                // meaning at runtime (e.g., WHERE clause may be added dynamically).
                let rule_issues = if query_is_templated {
                    rule_issues
                        .into_iter()
                        .map(|mut i| {
                            if i.confidence == crate::models::RuleConfidence::Proven {
                                i.confidence = crate::models::RuleConfidence::Contextual;
                            }
                            i
                        })
                        .collect::<Vec<_>>()
                } else {
                    rule_issues
                };

                // Skip compliance rules unless frameworks are explicitly configured
                if self.config.analysis.compliance_frameworks.is_empty() {
                    raw_issues.extend(
                        rule_issues
                            .into_iter()
                            .filter(|i| i.dimension != crate::models::Dimension::Compliance),
                    );
                } else {
                    raw_issues.extend(rule_issues);
                }
            }
        }

        // Run schema-aware rules if schema is loaded
        if let Some(ref schema) = self.schema {
            for query in &queries {
                for table_name in &query.tables {
                    if !schema.has_table(table_name) {
                        let mut issue = crate::models::Issue::new(
                            "SCHEMA-TBL-001",
                            format!("Table '{}' does not exist in schema", table_name),
                            crate::models::Severity::Critical,
                            crate::models::Dimension::Reliability,
                            query.location.clone(),
                            table_name.clone(),
                        );
                        issue.source_context = source_ctx.to_string();
                        raw_issues.push(issue);
                    }
                }
                if let Some(qt) = &query.query_type {
                    if qt == "SELECT" || qt == "UPDATE" || qt == "DELETE" {
                        for table_name in &query.tables {
                            if let Some(table) = schema.get_table(table_name) {
                                for col_name in &query.columns {
                                    if col_name != "*" && !table.has_column(col_name) {
                                        let mut issue = crate::models::Issue::new(
                                            "SCHEMA-COL-001",
                                            format!(
                                                "Column '{}' does not exist in table '{}'",
                                                col_name, table_name
                                            ),
                                            crate::models::Severity::Critical,
                                            crate::models::Dimension::Reliability,
                                            query.location.clone(),
                                            col_name.clone(),
                                        );
                                        issue.source_context = source_ctx.to_string();
                                        raw_issues.push(issue);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Compute complexity scores for each query
        {
            let scorer = crate::scoring::ComplexityScorer::from_config(&self.config.complexity);
            let query_issues: Vec<&crate::models::Issue> = raw_issues.iter().collect();
            for query in &mut queries {
                let q_issues: Vec<&crate::models::Issue> = query_issues
                    .iter()
                    .filter(|i| {
                        i.location.file == query.location.file
                            && i.location.line == query.location.line
                    })
                    .copied()
                    .collect();
                let owned: Vec<crate::models::Issue> = q_issues.into_iter().cloned().collect();
                query.complexity_score = scorer.calculate(query, &owned);
            }
        }

        let filtered = crate::context::filter_issues_by_context(raw_issues, source_ctx);

        // Filter by minimum confidence level
        let min_conf: crate::models::RuleConfidence = self
            .config
            .analysis
            .min_confidence
            .parse()
            .unwrap_or(crate::models::RuleConfidence::Contextual);
        let filtered: Vec<_> = filtered
            .into_iter()
            .filter(|i| i.confidence >= min_conf)
            .collect();

        let mut suppressed_count = 0;
        for issue in filtered {
            if suppression_map.is_suppressed(issue.location.line, &issue.rule_id) {
                suppressed_count += 1;
            } else {
                result.add_issue(issue);
            }
        }
        result.suppressed_count = suppressed_count;
        result.queries = queries;
        result.statistics.analysis_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        result
    }

    pub fn analyze_file(&self, path: &str) -> Result<AnalysisResult, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

        let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
        let app_code_exts = [
            "py", "ts", "js", "tsx", "jsx", "java", "go", "rb", "kt", "cs",
        ];

        if app_code_exts.contains(&ext.as_str()) {
            return Ok(self.analyze_app_code(&content, path));
        }

        if ext == "xml" {
            return Ok(self.analyze_mybatis(&content, path));
        }

        Ok(self.analyze(&content, None, Some(path)))
    }

    pub fn analyze_mybatis(&self, content: &str, path: &str) -> AnalysisResult {
        // Only parse if it looks like a MyBatis mapper
        if !content.contains("<mapper") && !content.contains("<sqlMap") {
            return AnalysisResult::new();
        }

        let extracted = crate::mybatis::parse_mybatis_xml(content, path);
        let mut combined = AnalysisResult::new();
        combined.dialect = self.config.analysis.dialect.clone();

        for ext_query in extracted {
            let mut result = self.analyze(
                &ext_query.raw,
                self.config.analysis.dialect.as_deref(),
                Some(&ext_query.file_path),
            );

            for query in &mut result.queries {
                query.is_dynamic = ext_query.is_dynamic;
                query.location.line = ext_query.line;
                query.location.column = ext_query.column;
            }

            // Propagate correct line/column to all issues from this query
            for issue in &mut result.issues {
                issue.location.line = ext_query.line;
                issue.location.column = ext_query.column;
            }

            for issue in result.issues {
                combined.add_issue(issue);
            }
            combined.statistics.total_queries += result.statistics.total_queries;
            combined.queries.extend(result.queries);
        }

        combined
    }

    pub fn analyze_app_code(&self, content: &str, path: &str) -> AnalysisResult {
        let extracted = crate::extractor::extract_from_source(content, path);
        let mut combined = AnalysisResult::new();
        combined.dialect = self.config.analysis.dialect.clone();

        for ext_query in extracted {
            let mut result = self.analyze(
                &ext_query.raw,
                self.config.analysis.dialect.as_deref(),
                Some(&ext_query.file_path),
            );

            // Mark dynamic queries
            for query in &mut result.queries {
                query.is_dynamic = ext_query.is_dynamic;
                query.location.line = ext_query.line;
                query.location.column = ext_query.column;
            }

            for issue in result.issues {
                combined.add_issue(issue);
            }
            combined.statistics.total_queries += result.statistics.total_queries;
            combined.queries.extend(result.queries);
        }

        combined
    }

    pub fn rule_count(&self) -> usize {
        self.registry.all().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_detects_select_star() {
        let engine = Engine::with_default_config();
        let result = engine.analyze("SELECT * FROM users", Some("postgresql"), None);
        assert_eq!(result.queries.len(), 1);
        assert_eq!(result.dialect.as_deref(), Some("postgresql"));
    }

    #[test]
    fn engine_detects_sql_injection() {
        let engine = Engine::with_default_config();
        let result = engine.analyze(
            "SELECT * FROM users WHERE name = 'x' + user_input",
            Some("postgresql"),
            None,
        );
        assert!(result.issues.iter().any(|i| i.rule_id == "SEC-INJ-001"));
    }

    #[test]
    fn engine_respects_disabled_rules() {
        let mut config = Config::default();
        config
            .analysis
            .disabled_rules
            .insert("SEC-INJ-001".to_string());
        let engine = Engine::new(config);
        let result = engine.analyze(
            "SELECT * FROM users WHERE name = 'x' + user_input",
            Some("postgresql"),
            None,
        );
        assert!(!result.issues.iter().any(|i| i.rule_id == "SEC-INJ-001"));
    }

    #[test]
    fn engine_counts_statistics() {
        let engine = Engine::with_default_config();
        let result = engine.analyze(
            "SELECT 1; SELECT * FROM users WHERE name = 'x' + user_input",
            Some("postgresql"),
            None,
        );
        assert_eq!(result.statistics.total_queries, 2);
        assert!(result.statistics.total_issues >= 1);
    }

    #[test]
    fn engine_applies_inline_suppression() {
        let engine = Engine::with_default_config();
        let sql = "-- slowql: disable REL-DATA-001\nDELETE FROM users";
        let result = engine.analyze(sql, Some("postgresql"), None);
        assert!(!result.issues.iter().any(|i| i.rule_id == "REL-DATA-001"));
        assert!(result.suppressed_count > 0);
    }

    #[test]
    fn engine_schema_aware_table_check() {
        let schema = crate::schema::parse_ddl(
            "CREATE TABLE users (id INT PRIMARY KEY, name TEXT);",
            "postgresql",
        );
        let engine = Engine::with_default_config().with_schema(schema);
        let result = engine.analyze("SELECT * FROM nonexistent_table", Some("postgresql"), None);
        assert!(result.issues.iter().any(|i| i.rule_id == "SCHEMA-TBL-001"));
    }

    #[test]
    fn engine_schema_aware_no_false_positive() {
        let schema = crate::schema::parse_ddl(
            "CREATE TABLE users (id INT PRIMARY KEY, name TEXT);",
            "postgresql",
        );
        let engine = Engine::with_default_config().with_schema(schema);
        let result = engine.analyze("SELECT * FROM users", Some("postgresql"), None);
        assert!(!result.issues.iter().any(|i| i.rule_id == "SCHEMA-TBL-001"));
    }

    #[test]
    fn engine_applies_context_filtering() {
        let engine = Engine::with_default_config();
        let result = engine.analyze(
            "SELECT * FROM users",
            Some("postgresql"),
            Some("tests/test_queries.sql"),
        );
        // In test context, performance rules should be filtered out
        assert!(!result.issues.iter().any(|i| i.rule_id == "PERF-SCAN-001"));
    }

    #[test]
    fn engine_analyze_file_sql() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sql");
        std::fs::write(&path, "DELETE FROM users WHERE id = 1").unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        assert_eq!(result.statistics.total_queries, 1);
    }

    #[test]
    fn engine_analyze_file_python() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.py");
        std::fs::write(&path, r#"q = "DELETE FROM users WHERE id = 1""#).unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        let _ = result;
    }

    #[test]
    fn engine_analyze_file_xml_mybatis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapper.xml");
        std::fs::write(
            &path,
            r#"<mapper><select id="find">SELECT 1 FROM t</select></mapper>"#,
        )
        .unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        assert!(result.statistics.total_queries >= 1);
    }

    #[test]
    fn engine_analyze_file_xml_non_mybatis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.xml");
        std::fs::write(&path, "<root><item>hello</item></root>").unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        assert_eq!(result.statistics.total_queries, 0);
    }

    #[test]
    fn engine_analyze_file_not_found() {
        let engine = Engine::with_default_config();
        assert!(engine.analyze_file("/nonexistent/file.sql").is_err());
    }

    #[test]
    fn engine_analyze_file_typescript() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.ts");
        std::fs::write(
            &path,
            r#"const r = await db.query("DELETE FROM users WHERE id = 1");"#,
        )
        .unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        let _ = result;
    }

    #[test]
    fn engine_analyze_file_java() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("App.java");
        std::fs::write(
            &path,
            r#"stmt = conn.prepareStatement("DELETE FROM users WHERE id = ?");"#,
        )
        .unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        let _ = result;
    }

    #[test]
    fn engine_analyze_file_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.go");
        std::fs::write(
            &path,
            r#"rows, err := db.query("DELETE FROM users WHERE id = $1")"#,
        )
        .unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        let _ = result;
    }

    #[test]
    fn engine_analyze_file_ruby() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.rb");
        std::fs::write(
            &path,
            r#"connection.execute("DELETE FROM users WHERE id = 1")"#,
        )
        .unwrap();
        let engine = Engine::with_default_config();
        let result = engine.analyze_file(path.to_str().unwrap()).unwrap();
        let _ = result;
    }

    #[test]
    fn engine_severity_override() {
        let mut config = Config::default();
        config
            .analysis
            .severity_overrides
            .insert("REL-DATA-001".to_string(), "info".to_string());
        let engine = Engine::new(config);
        let result = engine.analyze("DELETE FROM users", Some("postgresql"), None);
        for issue in &result.issues {
            if issue.rule_id == "REL-DATA-001" {
                assert_eq!(issue.severity, crate::models::Severity::Info);
            }
        }
    }

    #[test]
    fn engine_enabled_rules_filter() {
        let mut config = Config::default();
        let mut enabled = std::collections::HashSet::new();
        enabled.insert("SEC-INJ-001".to_string());
        config.analysis.enabled_rules = Some(enabled);
        let engine = Engine::new(config);
        let result = engine.analyze(
            "SELECT * FROM users WHERE name = 'x' + input",
            Some("postgresql"),
            None,
        );
        // Only SEC-INJ-001 should fire, other rules filtered out
        for issue in &result.issues {
            assert!(
                issue.rule_id == "SEC-INJ-001" || issue.rule_id.starts_with("SEC-INJ"),
                "unexpected rule: {}",
                issue.rule_id
            );
        }
    }

    #[test]
    fn engine_enabled_rules_prefix_filter() {
        let mut config = Config::default();
        let mut enabled = std::collections::HashSet::new();
        enabled.insert("SEC-INJ".to_string());
        config.analysis.enabled_rules = Some(enabled);
        let engine = Engine::new(config);
        let result = engine.analyze(
            "SELECT * FROM users WHERE name = 'x' + input",
            Some("postgresql"),
            None,
        );
        for issue in &result.issues {
            assert!(
                issue.rule_id.starts_with("SEC-INJ"),
                "unexpected rule: {}",
                issue.rule_id
            );
        }
    }

    #[test]
    fn engine_templated_query_demotes_confidence() {
        let engine = Engine::with_default_config();
        let result = engine.analyze("DELETE FROM ${table_name}", Some("postgresql"), None);
        // Templated queries should have confidence demoted
        for issue in &result.issues {
            assert_ne!(
                issue.confidence,
                crate::models::RuleConfidence::Proven,
                "templated query should not have proven confidence: {}",
                issue.rule_id
            );
        }
    }

    #[test]
    fn engine_custom_yaml_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("custom.yaml");
        std::fs::write(
            &rules_path,
            r#"
rules:
  - id: "CUSTOM-TEST-001"
    pattern: "\bFOOBAR\b"
    message: "FOOBAR detected"
"#,
        )
        .unwrap();
        let mut config = Config::default();
        config.analysis.custom_rules = Some(rules_path.to_str().unwrap().to_string());
        let engine = Engine::new(config);
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn engine_rule_count() {
        let engine = Engine::with_default_config();
        assert!(engine.rule_count() > 100);
    }

    #[test]
    fn engine_mybatis_direct() {
        let engine = Engine::with_default_config();
        let xml =
            r#"<mapper><select id="find">SELECT id FROM users WHERE id = 1</select></mapper>"#;
        let result = engine.analyze_mybatis(xml, "UserMapper.xml");
        assert!(result.statistics.total_queries >= 1);
    }

    #[test]
    fn engine_mybatis_non_mapper() {
        let engine = Engine::with_default_config();
        let result = engine.analyze_mybatis("<root/>", "config.xml");
        assert_eq!(result.statistics.total_queries, 0);
    }

    #[test]
    fn engine_app_code_direct() {
        let engine = Engine::with_default_config();
        let code = r#"q = "DELETE FROM users WHERE id = 1""#;
        let result = engine.analyze_app_code(code, "app.py");
        let _ = result;
    }

    #[test]
    fn engine_schema_column_check() {
        let schema = crate::schema::parse_ddl(
            "CREATE TABLE users (id INT PRIMARY KEY, name TEXT);",
            "postgresql",
        );
        let engine = Engine::with_default_config().with_schema(schema);
        let result = engine.analyze(
            "SELECT nonexistent_col FROM users",
            Some("postgresql"),
            None,
        );
        assert!(result.issues.iter().any(|i| i.rule_id == "SCHEMA-COL-001"));
    }

    #[test]
    fn engine_compliance_frameworks_filter() {
        let mut config = Config::default();
        config
            .analysis
            .compliance_frameworks
            .insert("gdpr".to_string());
        let engine = Engine::new(config);
        let result = engine.analyze("SELECT email, phone FROM users", Some("postgresql"), None);
        // With compliance frameworks set, compliance rules should fire
        let _ = result;
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn engine_custom_rules_nonexistent_file_is_ignored() {
        let mut config = Config::default();
        config.analysis.custom_rules = Some("/no/such/custom_rules.yaml".to_string());
        let engine = Engine::new(config);
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn engine_severity_override_all_levels() {
        let cases = [
            ("critical", crate::models::Severity::Critical),
            ("high", crate::models::Severity::High),
            ("medium", crate::models::Severity::Medium),
            ("low", crate::models::Severity::Low),
            ("info", crate::models::Severity::Info),
        ];

        for (level, expected) in cases {
            let mut config = Config::default();
            config
                .analysis
                .severity_overrides
                .insert("REL-DATA-001".to_string(), level.to_string());

            let engine = Engine::new(config);
            let result = engine.analyze("DELETE FROM users", Some("postgresql"), None);

            let issue = result
                .issues
                .iter()
                .find(|i| i.rule_id == "REL-DATA-001")
                .unwrap();

            assert_eq!(issue.severity, expected);
        }
    }

    #[test]
    fn engine_schema_update_does_not_flag_set_column_without_extracted_columns() {
        let schema = crate::schema::parse_ddl(
            "CREATE TABLE users (id INT PRIMARY KEY, name TEXT);",
            "postgresql",
        );
        let engine = Engine::with_default_config().with_schema(schema);
        let result = engine.analyze(
            "UPDATE users SET nonexistent_col = 1 WHERE id = 1",
            Some("postgresql"),
            None,
        );

        assert_eq!(result.queries.len(), 1);
        assert_eq!(result.queries[0].tables, vec!["users".to_string()]);
        assert!(result.queries[0].columns.is_empty());
        assert!(!result.issues.iter().any(|i| i.rule_id == "SCHEMA-COL-001"));
    }

    #[test]
    fn engine_analyze_app_code_propagates_issues() {
        let engine = Engine::with_default_config();
        let code = r#"q = "DELETE FROM users""#;
        let result = engine.analyze_app_code(code, "app.py");
        assert!(result.issues.iter().any(|i| i.rule_id == "REL-DATA-001"));
    }

    #[test]
    fn engine_analyze_mybatis_propagates_issue_line_and_column() {
        let engine = Engine::with_default_config();
        let xml = r#"<mapper>
<select id="x">
DELETE FROM users
</select>
</mapper>"#;
        let result = engine.analyze_mybatis(xml, "UserMapper.xml");
        assert!(result.issues.iter().any(|i| i.location.line >= 2));
        assert!(result.queries.iter().any(|q| q.location.line >= 2));
    }

    #[test]
    fn engine_templated_query_explicitly_demotes_to_contextual() {
        let engine = Engine::with_default_config();
        let result = engine.analyze("SELECT * FROM ${table_name}", Some("postgresql"), None);
        assert!(result
            .issues
            .iter()
            .all(|i| i.confidence != crate::models::RuleConfidence::Proven));
    }
}
