use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{Rule, RuleConfidence};

// SCH-BRK-001: Cross-file breaking change (project-level, check_project in Python)
pub struct CrossFileBreakingChangeRule;
impl Rule for CrossFileBreakingChangeRule {
    fn id(&self) -> &'static str {
        "SCH-BRK-001"
    }
    fn name(&self) -> &'static str {
        "Cross-File Breaking Change"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Schema
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn impact(&self) -> &'static str {
        "Destructive changes in one file can break queries in other files."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new()
    }
}

// SCHEMA-TBL-001: Non-existent table (requires loaded schema)
pub struct TableExistsRule;
impl Rule for TableExistsRule {
    fn id(&self) -> &'static str {
        "SCHEMA-TBL-001"
    }
    fn name(&self) -> &'static str {
        "Non-Existent Table"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn impact(&self) -> &'static str {
        "Query references a table that does not exist in the schema."
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires schema context */
    }
}

// SCHEMA-COL-001: Non-existent column (requires loaded schema)
pub struct ColumnExistsRule;
impl Rule for ColumnExistsRule {
    fn id(&self) -> &'static str {
        "SCHEMA-COL-001"
    }
    fn name(&self) -> &'static str {
        "Non-Existent Column"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Reliability
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn impact(&self) -> &'static str {
        "Query references a column that does not exist in the table."
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires schema context */
    }
}

// SCHEMA-IDX-001: Missing index on WHERE column (requires loaded schema)
pub struct MissingIndexRule;
impl Rule for MissingIndexRule {
    fn id(&self) -> &'static str {
        "SCHEMA-IDX-001"
    }
    fn name(&self) -> &'static str {
        "Missing Index on WHERE Column"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfIndex)
    }
    fn impact(&self) -> &'static str {
        "Query filters on a column without an index, causing full table scans."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires schema context */
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CrossFileBreakingChangeRule),
        Box::new(TableExistsRule),
        Box::new(ColumnExistsRule),
        Box::new(MissingIndexRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn all_schema_rules_metadata() {
        let rules = all_rules();
        assert_eq!(rules.len(), 4);
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
            // All schema rules return empty vec (require context)
            let issues = rule.check(&q("SELECT 1"));
            assert!(issues.is_empty());
        }
    }
}
