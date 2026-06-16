use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct CartesianProductRule;
static PAT_CROSS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCROSS\s+JOIN\b").unwrap());
impl Rule for CartesianProductRule {
    fn id(&self) -> &'static str { "PERF-JOIN-001" }
    fn name(&self) -> &'static str { "Cartesian Product (CROSS JOIN)" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn impact(&self) -> &'static str { "Produces row count = table1_rows * table2_rows, exponential cost." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CROSS.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "CROSS JOIN detected. This produces a Cartesian product.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct TooManyJoinsRule;
static PAT_JOIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bJOIN\b").unwrap());
impl Rule for TooManyJoinsRule {
    fn id(&self) -> &'static str { "PERF-JOIN-002" }
    fn name(&self) -> &'static str { "Excessive Joins" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn impact(&self) -> &'static str { "High join count increases query plan complexity and memory usage." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let count = PAT_JOIN.find_iter(&query.raw).count();
        if count >= 5 {
            let msg = format!("Query has {} JOINs. Consider simplifying.", count);
            let snip = &query.raw[..query.raw.len().min(80)];
            return vec![self.build_issue(query, &msg, snip)];
        }
        Vec::new()
    }
}

struct LeftJoinWithIsNotNullRule;
impl Rule for LeftJoinWithIsNotNullRule {
    fn id(&self) -> &'static str { "PERF-JOIN-003" }
    fn name(&self) -> &'static str { "LEFT JOIN With IS NOT NULL Filter" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn impact(&self) -> &'static str { "The LEFT JOIN preserves unmatched rows, then WHERE immediately removes them." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("LEFT JOIN") && upper.contains("IS NOT NULL") {
            let snip = &query.raw[..query.raw.len().min(80)];
            return vec![self.build_issue(query, "LEFT JOIN with IS NOT NULL filter - use INNER JOIN instead.", snip)];
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CartesianProductRule),
        Box::new(TooManyJoinsRule),
        Box::new(LeftJoinWithIsNotNullRule),
    ]
}
