use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

struct ScalarUdfInQueryRule;
static PAT_UDF: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(SELECT|WHERE)\b[^;]*\bdbo\.\w+\s*\([^)]*\)").unwrap());
impl Rule for ScalarUdfInQueryRule {
    fn id(&self) -> &'static str {
        "PERF-SCALAR-001"
    }
    fn name(&self) -> &'static str {
        "Scalar UDF in SELECT/WHERE"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfExecution)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "Scalar UDFs execute row-by-row, prevent parallelism. Can make queries 100x slower."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_UDF
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Scalar UDF detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct CorrelatedSubqueryRule;
// Heuristic: subquery that references outer table alias
impl Rule for CorrelatedSubqueryRule {
    fn id(&self) -> &'static str {
        "PERF-SCALAR-002"
    }
    fn name(&self) -> &'static str {
        "Correlated Subquery"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfExecution)
    }
    fn impact(&self) -> &'static str {
        "Correlated subqueries execute for every row in the outer query."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains("EXISTS") {
            return Vec::new();
        }
        // Simplified heuristic: subquery with reference to outer table
        let upper = query.raw_upper();
        if !upper.contains("(") || !upper.contains("SELECT") {
            return Vec::new();
        }
        // Look for pattern: WHERE x IN (SELECT ... FROM ... WHERE outer.col ...)
        // or WHERE EXISTS (SELECT ... WHERE outer.col ...)
        // This is a rough heuristic matching the Python behavior
        if let Some(pos) = upper.find("(SELECT") {
            let inner = &upper[pos..];
            // Check if inner references a table alias from outer context
            // Simple check: does the inner subquery contain a dot-qualified column?
            if inner.contains(".") && (inner.contains("WHERE") || inner.contains("ON")) {
                // Count dots in inner query as a proxy for correlated references
                let dot_count = inner.matches('.').count();
                if dot_count >= 2 {
                    let snip = query.snippet(100);
                    return vec![self.build_issue(
                        query,
                        "Correlated subquery detected - consider rewriting as JOIN.",
                        snip,
                    )];
                }
            }
        }
        Vec::new()
    }
}

struct OrderByNonIndexedColumnRule;
static NON_INDEXED_COLS: &[&str] = &[
    "description",
    "notes",
    "comments",
    "body",
    "content",
    "message",
    "address",
    "bio",
    "about",
    "metadata",
    "json_data",
    "xml_data",
];
impl Rule for OrderByNonIndexedColumnRule {
    fn id(&self) -> &'static str {
        "PERF-SORT-001"
    }
    fn name(&self) -> &'static str {
        "ORDER BY on Non-Indexed Column"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfSort)
    }
    fn impact(&self) -> &'static str {
        "Sorting without index requires loading all rows into memory."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("ORDER BY") {
            return Vec::new();
        }
        let raw_lower = query.raw_lower().to_string();
        for col in NON_INDEXED_COLS {
            if raw_lower.contains(&format!("order by {}", col))
                || raw_lower.contains(&format!("order by {}", col))
            {
                let msg = format!(
                    "ORDER BY on likely non-indexed column '{}' - may require expensive sort.",
                    col
                );
                let snip = query.snippet(100);
                return vec![self.build_issue(query, &msg, snip)];
            }
        }
        Vec::new()
    }
}

/// PERF-TSQL-004: WAITFOR DELAY blocks a connection and worker thread,
/// starving the connection pool under concurrent load.
struct TsqlWaitforDelayRule;
static PAT_TSQL_WAIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWAITFOR\s+DELAY\b").unwrap());

impl Rule for TsqlWaitforDelayRule {
    fn id(&self) -> &'static str {
        "PERF-TSQL-004"
    }
    fn name(&self) -> &'static str {
        "WAITFOR DELAY in Production Code"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfExecution)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "WAITFOR DELAY ties up a connection and worker thread, exhausting the connection pool under load."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_TSQL_WAIT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!(
                        "WAITFOR DELAY detected - testing artifact or blind injection vector: {}",
                        m.as_str()
                    ),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ScalarUdfInQueryRule),
        Box::new(CorrelatedSubqueryRule),
        Box::new(OrderByNonIndexedColumnRule),
        Box::new(TsqlWaitforDelayRule),
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

    fn q(sql: &str, dialect: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: dialect.to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn correlated_subquery_positive() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-SCALAR-002").unwrap();

        let sql = "SELECT * FROM users u WHERE u.id IN (SELECT o.user_id FROM orders o WHERE o.user_id = u.id)";
        let query = q(sql, "postgresql");

        let issues = rule.check(&query);
        assert!(!issues.is_empty());
    }

    #[test]
    fn correlated_subquery_exists_is_skipped() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-SCALAR-002").unwrap();

        let sql =
            "SELECT * FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)";
        let query = q(sql, "postgresql");

        let issues = rule.check(&query);
        assert!(issues.is_empty());
    }

    #[test]
    fn correlated_subquery_single_dot_no_fire() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "PERF-SCALAR-002").unwrap();

        let sql = "SELECT * FROM users u WHERE u.id IN (SELECT o.user_id FROM orders o)";
        let query = q(sql, "postgresql");

        let issues = rule.check(&query);
        assert!(issues.is_empty());
    }
}
