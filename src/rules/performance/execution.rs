use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, RuleConfidence, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct ScalarUdfInQueryRule;
static PAT_UDF: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(SELECT|WHERE)\b[^;]*\bdbo\.\w+\s*\([^)]*\)").unwrap());
impl Rule for ScalarUdfInQueryRule {
    fn id(&self) -> &'static str { "PERF-SCALAR-001" }
    fn name(&self) -> &'static str { "Scalar UDF in SELECT/WHERE" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfExecution) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Scalar UDFs execute row-by-row, prevent parallelism. Can make queries 100x slower." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_UDF.find(&query.raw).map(|m| {
            let msg = format!("Scalar UDF detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct CorrelatedSubqueryRule;
// Heuristic: subquery that references outer table alias
impl Rule for CorrelatedSubqueryRule {
    fn id(&self) -> &'static str { "PERF-SCALAR-002" }
    fn name(&self) -> &'static str { "Correlated Subquery" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfExecution) }
    fn impact(&self) -> &'static str { "Correlated subqueries execute for every row in the outer query." }
    
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Contextual }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains("EXISTS") { return Vec::new(); }
        // Simplified heuristic: subquery with reference to outer table
        let upper = query.raw_upper();
        if !upper.contains("(") || !upper.contains("SELECT") { return Vec::new(); }
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
                    let snip = &query.raw[..query.raw.len().min(100)];
                    return vec![self.build_issue(query, "Correlated subquery detected - consider rewriting as JOIN.", snip)];
                }
            }
        }
        Vec::new()
    }
}

struct OrderByNonIndexedColumnRule;
static NON_INDEXED_COLS: &[&str] = &[
    "description", "notes", "comments", "body", "content", "message",
    "address", "bio", "about", "metadata", "json_data", "xml_data",
];
impl Rule for OrderByNonIndexedColumnRule {
    fn id(&self) -> &'static str { "PERF-SORT-001" }
    fn name(&self) -> &'static str { "ORDER BY on Non-Indexed Column" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfSort) }
    fn impact(&self) -> &'static str { "Sorting without index requires loading all rows into memory." }
    
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Advisory }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("ORDER BY") { return Vec::new(); }
        let raw_lower = query.raw_lower().to_string();
        for col in NON_INDEXED_COLS {
            if raw_lower.contains(&format!("order by {}", col)) || raw_lower.contains(&format!("order by {}", col)) {
                let msg = format!("ORDER BY on likely non-indexed column '{}' - may require expensive sort.", col);
                let snip = &query.raw[..query.raw.len().min(100)];
                return vec![self.build_issue(query, &msg, snip)];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ScalarUdfInQueryRule),
        Box::new(CorrelatedSubqueryRule),
        Box::new(OrderByNonIndexedColumnRule),
    ]
}
