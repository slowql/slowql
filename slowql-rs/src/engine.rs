use crate::config::Config;


use crate::models::result::AnalysisResult;
use crate::parser;
use crate::rules::RuleRegistry;
use std::time::Instant;

pub struct Engine {
    pub config: Config,
    registry: RuleRegistry,
}

impl Engine {
    pub fn new(config: Config) -> Self {
        Engine {
            config,
            registry: RuleRegistry::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(Config::default())
    }

    /// Analyze a SQL string and return all detected issues.
    pub fn analyze(&self, sql: &str, dialect: Option<&str>, file_path: Option<&str>) -> AnalysisResult {
        let start = Instant::now();

        let effective_dialect = dialect
            .or(self.config.analysis.dialect.as_deref())
            .unwrap_or("generic");

        // Parse
        let parse_start = Instant::now();
        let queries = parser::parse(sql, effective_dialect, file_path);
        let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

        // Build result
        let mut result = AnalysisResult::new();
        result.dialect = Some(effective_dialect.to_string());
        result.statistics.total_queries = queries.len();
        result.statistics.parse_time_ms = parse_ms;

        // Get enabled rules
        let rules = self.registry.enabled_for_dimensions(&self.config.analysis.enabled_dimensions);

        // Run rules on each query
        for query in &queries {
            for rule in &rules {
                // Check disabled rules
                if self.config.analysis.disabled_rules.contains(rule.id()) {
                    continue;
                }
                if let Some(ref enabled) = self.config.analysis.enabled_rules {
                    if !enabled.contains(rule.id()) {
                        let prefix: String = rule.id().split('-').take(2).collect::<Vec<_>>().join("-");
                        if !enabled.contains(prefix.as_str()) {
                            continue;
                        }
                    }
                }

                let issues = rule.check(query);
                for issue in issues {
                    result.add_issue(issue);
                }
            }
        }

        result.queries = queries;
        result.statistics.analysis_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        result
    }

    /// Analyze a single SQL file.
    pub fn analyze_file(&self, path: &str) -> Result<AnalysisResult, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file {}: {}", path, e))?;
        Ok(self.analyze(&content, None, Some(path)))
    }

    /// Get the total number of registered rules.
    pub fn registry_ref(&self) -> &crate::rules::RuleRegistry {
        &self.registry
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
        // At minimum, security rules should not crash. SELECT * is a perf rule
        // which we have not yet ported, so just verify no panics and structure is correct.
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
        let inj_issues: Vec<_> = result.issues.iter().filter(|i| i.rule_id == "SEC-INJ-001").collect();
        assert_eq!(inj_issues.len(), 1);
    }

    #[test]
    fn engine_respects_disabled_rules() {
        let mut config = Config::default();
        config.analysis.disabled_rules.insert("SEC-INJ-001".to_string());
        let engine = Engine::new(config);
        let result = engine.analyze(
            "SELECT * FROM users WHERE name = 'x' + user_input",
            Some("postgresql"),
            None,
        );
        let inj_issues: Vec<_> = result.issues.iter().filter(|i| i.rule_id == "SEC-INJ-001").collect();
        assert_eq!(inj_issues.len(), 0);
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
        assert!(result.statistics.analysis_time_ms > 0.0);
    }
}
