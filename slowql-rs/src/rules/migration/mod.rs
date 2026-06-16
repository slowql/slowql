use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;

pub struct BreakingChangeRule;

impl Rule for BreakingChangeRule {
    fn id(&self) -> &'static str { "MIG-BRK-001" }
    fn name(&self) -> &'static str { "Breaking Schema Change" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Migration }
    fn category(&self) -> Option<Category> { Some(Category::RelDataIntegrity) }
    fn impact(&self) -> &'static str { "Dropping tables or columns can break existing application code." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("DROP TABLE") {
            return vec![self.build_issue(query, "Breaking Change: dropping table.", query.snippet(100))];
        }
        if upper.contains("ALTER TABLE") && upper.contains("DROP COLUMN") {
            return vec![self.build_issue(query, "Breaking Change: dropping column.", query.snippet(100))];
        }
        Vec::new()
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(BreakingChangeRule)]
}
