use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, RuleConfidence, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct QueryOptimizerHintRule;
static PAT_HINT_001: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOPTION\s*\(\s*(FORCE\s+ORDER|HASH\s+JOIN|MERGE\s+JOIN|LOOP\s+JOIN|FAST\s+\d+|RECOMPILE|OPTIMIZE\s+FOR|MAXDOP|QUERYTRACEON|USE\s+PLAN)\b").unwrap());
impl Rule for QueryOptimizerHintRule {
    fn id(&self) -> &'static str { "PERF-HINT-001" }
    fn name(&self) -> &'static str { "Query Optimizer Hint" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfHints) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Query hints freeze execution plans. As data grows, hinted plans become suboptimal." }
    
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Advisory }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_HINT_001.find(&query.raw).map(|m| {
            let msg = format!("Query optimizer hint detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct IndexHintRule;
static PAT_HINT_002: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(FORCE\s+INDEX|USE\s+INDEX|IGNORE\s+INDEX|WITH\s*\(\s*INDEX\s*[=(])\b").unwrap());
impl Rule for IndexHintRule {
    fn id(&self) -> &'static str { "PERF-HINT-002" }
    fn name(&self) -> &'static str { "Index Hint" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfHints) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["mysql", "tsql"]) }
    fn impact(&self) -> &'static str { "Index hints force specific index usage regardless of statistics." }
    
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Advisory }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_HINT_002.find(&query.raw).map(|m| {
            let msg = format!("Index hint detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct ParallelQueryHintRule;
static PAT_HINT_003: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOPTION\s*\([^)]*MAXDOP\s+\d+").unwrap());
impl Rule for ParallelQueryHintRule {
    fn id(&self) -> &'static str { "PERF-HINT-003" }
    fn name(&self) -> &'static str { "Parallel Query Hint" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfHints) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "MAXDOP hints override server-level parallelism." }
    
    fn confidence(&self) -> RuleConfidence { RuleConfidence::Advisory }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_HINT_003.find(&query.raw).map(|m| {
            let msg = format!("Parallel query hint (MAXDOP) detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(QueryOptimizerHintRule),
        Box::new(IndexHintRule),
        Box::new(ParallelQueryHintRule),
    ]
}
