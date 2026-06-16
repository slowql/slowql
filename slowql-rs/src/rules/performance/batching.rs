use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct LargeUnbatchedOperationRule;
impl Rule for LargeUnbatchedOperationRule {
    fn id(&self) -> &'static str { "PERF-BATCH-001" }
    fn name(&self) -> &'static str { "Large Unbatched Operation" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfBatch) }
    fn impact(&self) -> &'static str { "Unbatched mass operations generate massive transaction logs and hold locks." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" { return Vec::new(); }
        let upper = query.raw_upper();
        if upper.contains("TOP") || upper.contains("LIMIT") { return Vec::new(); }
        let msg = format!("Unbatched {} without row limit - affects entire table.", qt);
        let snip = &query.raw[..query.raw.len().min(100)];
        vec![self.build_issue(query, &msg, snip)]
    }
}

// Rewritten without look-ahead: match WHILE...END block, then check absence of TOP/LIMIT
struct MissingBatchSizeInLoopRule;
static PAT_WHILE_DML: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\bWHILE\b[\s\S]*?\b(UPDATE|DELETE)\b[\s\S]*?\bEND\b").unwrap()
});
impl Rule for MissingBatchSizeInLoopRule {
    fn id(&self) -> &'static str { "PERF-BATCH-002" }
    fn name(&self) -> &'static str { "Missing Batch Size in Loop" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfBatch) }
    fn impact(&self) -> &'static str { "WHILE loops without batch limits may process unlimited rows per iteration." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_WHILE_DML.find(&query.raw) {
            let matched = m.as_str().to_uppercase();
            if !matched.contains("TOP") && !matched.contains("LIMIT") {
                return vec![self.build_issue(query, "WHILE loop with unbatched DML detected.", &query.raw[..query.raw.len().min(80)])];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LargeUnbatchedOperationRule),
        Box::new(MissingBatchSizeInLoopRule),
    ]
}
