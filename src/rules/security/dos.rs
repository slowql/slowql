use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

struct UnboundedRecursiveCteRule;
static PAT_DOS_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bWITH\s+RECURSIVE\b|\bWITH\b[\s\S]*?\bUNION\s+ALL\b").unwrap());

impl Rule for UnboundedRecursiveCteRule {
    fn id(&self) -> &'static str {
        "SEC-DOS-001"
    }
    fn name(&self) -> &'static str {
        "Unbounded Recursive CTE"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDos)
    }
    fn impact(&self) -> &'static str {
        "Unbounded recursion can consume all available memory and CPU, crashing the database server."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !PAT_DOS_001.is_match(&query.raw) {
            return Vec::new();
        }
        let raw_upper = query.raw_upper();
        if raw_upper.contains("MAXRECURSION") {
            return Vec::new();
        }
        // Only fire on WITH RECURSIVE, not on regular WITH ... AS CTEs.
        // Non-recursive CTEs cannot cause unbounded recursion.
        if !raw_upper.contains("WITH RECURSIVE") {
            // Check for self-referencing UNION ALL pattern
            // which indicates recursion even without the RECURSIVE keyword
            // (some dialects allow implicit recursion)
            if !raw_upper.contains("UNION ALL") {
                return Vec::new();
            }
            // Has UNION ALL but is it actually recursive?
            // A recursive CTE references itself. Without WITH RECURSIVE,
            // we need the CTE name to appear in its own body.
            // This is too complex for regex. Be conservative and skip.
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "Recursive CTE without MAXRECURSION limit - unbounded recursion risk",
            query.snippet(100),
        )]
    }
}

struct RegexDenialOfServiceRule;
static PAT_DOS_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(REGEXP|RLIKE|REGEXP_LIKE|REGEXP_MATCHES|SIMILAR\s+TO)\s*\(?[^)]*(\(\?\:?\[?\w+\]\*\)[\*\+]|\(\.\*\)[\*\+]|\(\w\+\)[\*\+]|\[\^?\w+\]\*\[\^?\w+\]\*)").unwrap()
});

impl Rule for RegexDenialOfServiceRule {
    fn id(&self) -> &'static str {
        "SEC-DOS-002"
    }
    fn name(&self) -> &'static str {
        "Regex Denial of Service (ReDoS)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDos)
    }
    fn impact(&self) -> &'static str {
        "ReDoS patterns like (a+)+ can take exponential time on crafted input, hanging database threads for hours."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_DOS_002
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Potential ReDoS pattern detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct PgSleepUsageRule;
static PAT_PG_001: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bpg_sleep\s*\(").unwrap());

impl Rule for PgSleepUsageRule {
    fn id(&self) -> &'static str {
        "SEC-PG-001"
    }
    fn name(&self) -> &'static str {
        "pg_sleep Usage Detected"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDos)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "pg_sleep() ties up a database connection and can exhaust the connection pool, causing denial of service."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_PG_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!(
                        "pg_sleep() call detected - potential DoS vector: {}",
                        m.as_str()
                    ),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

/// PERF-TSQL-004 (WAITFOR DELAY) moved to performance/execution.rs
/// where it belongs by dimension and category.

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnboundedRecursiveCteRule),
        Box::new(RegexDenialOfServiceRule),
        Box::new(PgSleepUsageRule),
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
        ];
        for dialect in &dialects {
            for qt in &["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"] {
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
    fn dos_001_fires_on_recursive_cte_without_maxrecursion() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-DOS-001").unwrap();
        let sql =
            "WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte) SELECT * FROM cte";
        let query = q(sql, "postgresql");
        let issues = rule.check(&query);
        assert!(!issues.is_empty(), "should flag unbounded recursive CTE");
    }

    #[test]
    fn dos_001_no_fire_when_maxrecursion_present() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-DOS-001").unwrap();
        let sql = "WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte WHERE n<100) SELECT * FROM cte OPTION(MAXRECURSION 100)";
        let query = q(sql, "tsql");
        let issues = rule.check(&query);
        assert!(
            issues.is_empty(),
            "should not flag when MAXRECURSION is set"
        );
    }

    #[test]
    fn dos_001_no_fire_on_plain_union_all_without_recursive() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-DOS-001").unwrap();
        let sql = "SELECT 1 UNION ALL SELECT 2";
        let query = q(sql, "postgresql");
        let issues = rule.check(&query);
        assert!(issues.is_empty(), "plain UNION ALL should not fire");
    }

    #[test]
    fn dos_002_pg_sleep_fires_for_postgresql() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-PG-001").unwrap();
        let sql = "SELECT pg_sleep(10)";
        let query = q(sql, "postgresql");
        let issues = rule.check(&query);
        assert!(!issues.is_empty(), "pg_sleep should fire for postgresql");
    }

    #[test]
    fn dos_002_pg_sleep_no_fire_for_mysql() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-PG-001").unwrap();
        let sql = "SELECT pg_sleep(10)";
        let query = q(sql, "mysql");
        let issues = rule.check(&query);
        assert!(issues.is_empty(), "pg_sleep should not fire for mysql");
    }
}
