use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;

pub struct BreakingChangeRule;

impl Rule for BreakingChangeRule {
    fn id(&self) -> &'static str {
        "MIG-BRK-001"
    }
    fn name(&self) -> &'static str {
        "Breaking Schema Change"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Migration
    }
    fn category(&self) -> Option<Category> {
        Some(Category::RelDataIntegrity)
    }
    fn impact(&self) -> &'static str {
        "Dropping tables or columns can break existing application code."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("DROP TABLE") {
            return vec![self.build_issue(
                query,
                "Breaking Change: dropping table.",
                query.snippet(100),
            )];
        }
        if upper.contains("ALTER TABLE") && upper.contains("DROP COLUMN") {
            return vec![self.build_issue(
                query,
                "Breaking Change: dropping column.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(BreakingChangeRule)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn all_migration_rules_metadata() {
        let rules = all_rules();
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
    fn migration_rules_check_paths() {
        let rules = all_rules();
        let queries = vec![
            q("SELECT 1", "SELECT"),
            q("DROP TABLE users", "DROP"),
            q("DROP COLUMN email", "ALTER"),
            q("ALTER TABLE t DROP COLUMN x", "ALTER"),
        ];
        for query in &queries {
            for rule in &rules {
                let _ = rule.check(query);
            }
        }
    }
}
