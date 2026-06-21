use crate::config::TableMetadata;
pub use crate::models::issue::RuleConfidence;
use crate::models::issue::{Category, Fix};
use crate::models::{Dimension, Issue, Query, Severity};
use crate::schema::Schema;

/// Context passed to rules that need metadata beyond the query itself.
/// This enables rules to make provable decisions instead of heuristic guesses.
pub struct RuleContext<'a> {
    /// Schema metadata (tables, columns, indexes, partitions).
    /// None when no --schema flag is provided.
    pub schema: Option<&'a Schema>,
    /// User-declared table metadata from config.
    /// Always present (defaults to empty).
    pub table_metadata: &'a TableMetadata,
    /// Source context string (adhoc, application, migration, test, seed, etc.)
    pub source_context: &'a str,
}

impl<'a> RuleContext<'a> {
    /// Check if a table is declared as large by the user or schema.
    pub fn is_large_table(&self, table_name: &str) -> bool {
        let lower = table_name.to_lowercase();
        // Check user-declared large tables
        if self
            .table_metadata
            .large_tables
            .iter()
            .any(|t| t.to_lowercase() == lower)
        {
            return true;
        }
        // Check schema estimated rows
        if let Some(schema) = self.schema {
            if let Some(table) = schema.get_table(table_name) {
                if let Some(rows) = table.estimated_rows {
                    return rows >= 1_000_000;
                }
            }
        }
        false
    }

    /// Check if a table is declared as partitioned by the user or schema.
    pub fn is_partitioned(&self, table_name: &str) -> bool {
        let lower = table_name.to_lowercase();
        // Check user-declared partitioned tables
        if self
            .table_metadata
            .partitioned_tables
            .keys()
            .any(|t| t.to_lowercase() == lower)
        {
            return true;
        }
        // Check schema partition columns
        if let Some(schema) = self.schema {
            if let Some(table) = schema.get_table(table_name) {
                return !table.partition_columns.is_empty();
            }
        }
        false
    }

    /// Get partition columns for a table, if known.
    pub fn partition_columns(&self, table_name: &str) -> Vec<String> {
        let lower = table_name.to_lowercase();
        // Check user-declared first
        if let Some(cols) = self
            .table_metadata
            .partitioned_tables
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.clone())
        {
            return cols;
        }
        // Check schema
        if let Some(schema) = self.schema {
            if let Some(table) = schema.get_table(table_name) {
                return table.partition_columns.clone();
            }
        }
        Vec::new()
    }
}

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
    pub fn universal() -> Self {
        DialectSet(Vec::new())
    }

    pub fn new(dialects: &[&'static str]) -> Self {
        DialectSet(dialects.to_vec())
    }

    pub fn matches(&self, query_dialect: &str) -> bool {
        if self.0.is_empty() {
            return true;
        }
        if query_dialect == "unknown" || query_dialect.is_empty() {
            return false;
        }
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
    fn category(&self) -> Option<Category> {
        None
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::universal()
    }
    fn impact(&self) -> &'static str {
        ""
    }
    fn fix_guidance(&self) -> &'static str {
        ""
    }
    /// How certain this rule is about its findings.
    /// Default: Proven. Override to Contextual or Advisory for heuristic rules.
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Proven
    }

    fn dialect_matches(&self, query: &Query) -> bool {
        self.dialects().matches(&query.dialect)
    }

    fn check(&self, query: &Query) -> Vec<Issue>;

    /// Check with full context. Override this instead of check() when
    /// the rule needs schema or table metadata for accurate analysis.
    /// Default implementation delegates to check() for backward compatibility.
    fn check_with_context(&self, query: &Query, _ctx: &RuleContext) -> Vec<Issue> {
        self.check(query)
    }

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
        issue.documentation_url = Some(format!(
            "https://slowql.dev/rules/{}",
            self.id().to_lowercase()
        ));
        if let Some(cat) = self.category() {
            issue.category = Some(cat);
        }
        if !self.impact().is_empty() {
            issue.impact = Some(self.impact().to_string());
        }
        issue.confidence = self.confidence();
        issue.source_context = query.source_context.clone();
        issue
    }

    fn build_issue_with_fix(&self, query: &Query, message: &str, snippet: &str, fix: Fix) -> Issue {
        self.build_issue(query, message, snippet).with_fix(fix)
    }
}
