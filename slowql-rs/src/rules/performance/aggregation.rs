use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct UnfilteredAggregationRule;
impl Rule for UnfilteredAggregationRule {
    fn id(&self) -> &'static str { "PERF-AGG-001" }
    fn name(&self) -> &'static str { "Unfiltered Aggregation" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfAggregation) }
    fn impact(&self) -> &'static str { "Aggregates entire table, expensive on large datasets." }
fn check(&self, query: &Query) -> Vec<Issue> { if !query.is_select() { return Vec::new(); } if query.source_context == "adhoc" || query.source_context.is_empty() { return Vec::new(); } let upper = query.raw_upper(); let has_agg = upper.contains("COUNT(") || upper.contains("SUM(") || upper.contains("AVG("); if has_agg && !upper.contains("WHERE") { let snip = &query.raw[..query.raw.len().min(80)]; return vec![self.build_issue(query, "Aggregation without WHERE clause scans entire table.", snip)]; } Vec::new() } }

struct OrderByInSubqueryRule;
static PAT_ORDER_SUB: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\(\s*SELECT\b[^)]+\bORDER\s+BY\b").unwrap());
impl Rule for OrderByInSubqueryRule {
    fn id(&self) -> &'static str { "PERF-AGG-002" }
    fn name(&self) -> &'static str { "ORDER BY in Subquery" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfAggregation) }
    fn impact(&self) -> &'static str { "ORDER BY in subquery is meaningless and wastes sort cost." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_ORDER_SUB.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "ORDER BY in subquery is typically meaningless.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct HavingWithoutGroupByRule;
impl Rule for HavingWithoutGroupByRule {
    fn id(&self) -> &'static str { "PERF-AGG-003" }
    fn name(&self) -> &'static str { "HAVING Without GROUP BY" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfAggregation) }
    fn impact(&self) -> &'static str { "Without GROUP BY, HAVING filters the entire table as one group." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("HAVING") && !upper.contains("GROUP BY") {
            let snip = &query.raw[..query.raw.len().min(80)];
            return vec![self.build_issue(query, "HAVING without GROUP BY - entire result treated as single group.", snip)];
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnfilteredAggregationRule),
        Box::new(OrderByInSubqueryRule),
        Box::new(HavingWithoutGroupByRule),
    ]
}
