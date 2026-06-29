use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct LargeUnbatchedOperationRule;
impl Rule for LargeUnbatchedOperationRule {
    fn id(&self) -> &'static str {
        "PERF-BATCH-001"
    }
    fn name(&self) -> &'static str {
        "Large Unbatched Operation"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfBatch)
    }
    fn impact(&self) -> &'static str {
        "Unbatched mass operations generate massive transaction logs and hold locks."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("TOP") || upper.contains("LIMIT") {
            return Vec::new();
        }
        if upper.contains("WHERE") {
            return Vec::new();
        }
        // Suppress intentional bulk operations (flush, clear, reset)
        if let Some(ref file) = query.location.file {
            let fl = file.to_lowercase();
            let filename = fl.rsplit('/').next().unwrap_or(&fl);
            if fl.contains("cache")
                || fl.contains("clear")
                || fl.contains("reset")
                || fl.contains("cleanup")
                || fl.contains("purge")
                || fl.contains("flush")
                || fl.contains("init.sql")
                || fl.contains("setup.sql")
                || fl.contains("teardown")
                || fl.contains("truncate")
                || filename.contains("flush")
                || filename.contains("clear")
                || filename.contains("reset")
                || filename.contains("purge")
                || filename.contains("testinfra")
                || filename.contains("sync")
            {
                return Vec::new();
            }
        }
        let msg = format!("Unbatched {} without row limit - affects entire table.", qt);
        let snip = query.snippet(100);
        vec![self.build_issue(query, &msg, snip)]
    }
}

// Rewritten without look-ahead: match WHILE...END block, then check absence of TOP/LIMIT
struct MissingBatchSizeInLoopRule;
static PAT_WHILE_DML: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)\bWHILE\b[\s\S]*?\b(UPDATE|DELETE)\b[\s\S]*?\bEND\b").unwrap());
impl Rule for MissingBatchSizeInLoopRule {
    fn id(&self) -> &'static str {
        "PERF-BATCH-002"
    }
    fn name(&self) -> &'static str {
        "Missing Batch Size in Loop"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfBatch)
    }
    fn impact(&self) -> &'static str {
        "WHILE loops without batch limits may process unlimited rows per iteration."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_WHILE_DML.find(&query.raw) {
            let matched = m.as_str().to_uppercase();
            if !matched.contains("TOP") && !matched.contains("LIMIT") {
                return vec![self.build_issue(
                    query,
                    "WHILE loop with unbatched DML detected.",
                    query.snippet(80),
                )];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LargeUnbatchedOperationRule),
        Box::new(MissingBatchSizeInLoopRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

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

    #[test]
    fn metadata_coverage() {
        let rules = rules();
        for rule in &rules {
            let _ = rule.id();
            let _ = rule.name();
            let _ = rule.severity();
            let _ = rule.dimension();
            let _ = rule.category();
            let _ = rule.impact();
            let _ = rule.fix_guidance();
            let _ = rule.confidence();
            let _ = rule.dialects();
        }
    }

    #[test]
    fn no_match_simple() {
        let rules = rules();
        let query = q("SELECT 1", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn dialect_coverage() {
        let rules = rules();
        let dialects = [
            "postgresql",
            "mysql",
            "tsql",
            "oracle",
            "sqlite",
            "bigquery",
            "snowflake",
            "redshift",
            "clickhouse",
            "duckdb",
            "presto",
            "spark",
        ];
        for dialect in &dialects {
            for qt in &["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE"] {
                let query = q("SELECT 1", dialect, qt);
                for rule in &rules {
                    let _ = rule.check(&query);
                    let _ = rule.dialect_matches(&query);
                }
            }
        }
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "tsql".to_string(),
            location: Location::new(1, 1),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    fn q_with_file(sql: &str, qt: &str, file: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "tsql".to_string(),
            location: Location::new(1, 1).with_file(file),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn batch_001_unbatched_update_fires() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-BATCH-001").unwrap();
        let query = q("UPDATE users SET active = 0", "UPDATE");
        let issues = rule.check(&query);
        assert!(!issues.is_empty(), "unbatched UPDATE should fire");
    }

    #[test]
    fn batch_001_no_fire_when_where_present() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-BATCH-001").unwrap();
        let query = q("UPDATE users SET active = 0 WHERE id = 1", "UPDATE");
        let issues = rule.check(&query);
        assert!(issues.is_empty(), "UPDATE with WHERE should not fire");
    }

    #[test]
    fn batch_001_no_fire_for_cleanup_file() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-BATCH-001").unwrap();
        let query = q_with_file(
            "UPDATE cache SET val = null",
            "UPDATE",
            "scripts/cache_clear.sql",
        );
        let issues = rule.check(&query);
        assert!(issues.is_empty(), "cache clear file should suppress");
    }

    #[test]
    fn batch_002_while_without_limit_fires() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-BATCH-002").unwrap();
        let sql = "WHILE @@ROWCOUNT > 0 BEGIN UPDATE users SET active = 0 END";
        let query = q(sql, "UPDATE");
        let issues = rule.check(&query);
        assert!(!issues.is_empty(), "WHILE without TOP or LIMIT should fire");
    }

    #[test]
    fn batch_002_no_fire_when_top_present() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-BATCH-002").unwrap();
        let sql = "WHILE @@ROWCOUNT > 0 BEGIN UPDATE TOP(1000) users SET active = 0 END";
        let query = q(sql, "UPDATE");
        let issues = rule.check(&query);
        assert!(issues.is_empty(), "WHILE with TOP should not fire");
    }
}
