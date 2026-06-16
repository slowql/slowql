use crate::models::issue::{Category, Fix};
use crate::models::{Dimension, Issue, Query, Severity};

pub fn normalize_dialect(dialect: &str) -> String {
    match dialect.to_lowercase().trim() {
        "postgres" | "pg" => "postgresql".to_string(),
        "mssql" | "sqlserver" | "sql_server" => "tsql".to_string(),
        "mariadb" => "mysql".to_string(),
        "bq" => "bigquery".to_string(),
        "sf" => "snowflake".to_string(),
        d => d.to_string(),
    }
}

pub struct DialectSet(Vec<&'static str>);

impl DialectSet {
    pub fn universal() -> Self { DialectSet(Vec::new()) }

    pub fn new(dialects: &[&'static str]) -> Self { DialectSet(dialects.to_vec()) }

    pub fn matches(&self, query_dialect: &str) -> bool {
        if self.0.is_empty() { return true; }
        if query_dialect == "unknown" || query_dialect.is_empty() { return false; }
        let qd = normalize_dialect(query_dialect);
        self.0.iter().any(|&d| normalize_dialect(d) == qd)
    }
}

/// Core rule trait. No generic methods — fully dyn-compatible.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn dimension(&self) -> Dimension;
    fn category(&self) -> Option<Category> { None }
    fn dialects(&self) -> DialectSet { DialectSet::universal() }
    fn impact(&self) -> &'static str { "" }
    fn fix_guidance(&self) -> &'static str { "" }

    fn dialect_matches(&self, query: &Query) -> bool {
        self.dialects().matches(&query.dialect)
    }

    fn check(&self, query: &Query) -> Vec<Issue>;

    /// Build an issue. Takes &str — no generics, fully dyn-compatible.
    fn build_issue(&self, query: &Query, message: &str, snippet: &str) -> Issue {
        let mut issue = Issue::new(
            self.id(),
            message.to_string(),
            self.severity(),
            self.dimension(),
            query.location.clone(),
            snippet.to_string(),
        );
        issue.documentation_url = Some(format!("https://slowql.dev/rules/{}", self.id().to_lowercase()));
        if let Some(cat) = self.category() { issue.category = Some(cat); }
        if !self.impact().is_empty() { issue.impact = Some(self.impact().to_string()); }
        issue
    }

    fn build_issue_with_fix(&self, query: &Query, message: &str, snippet: &str, fix: Fix) -> Issue {
        self.build_issue(query, message, snippet).with_fix(fix)
    }
}
