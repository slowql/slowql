use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct LargeInClauseRule;
static PAT_IN_CLAUSE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bIN\s*\(").unwrap());
impl Rule for LargeInClauseRule {
    fn id(&self) -> &'static str { "PERF-MEM-001" }
    fn name(&self) -> &'static str { "Large IN Clause" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn impact(&self) -> &'static str { "Large IN clauses (100+ values) consume memory and bloat the plan cache." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Count commas inside IN(...) as proxy for value count
        if let Some(m) = PAT_IN_CLAUSE.find(&query.raw) {
            let after = &query.raw[m.end()..];
            if let Some(close) = after.find(')') {
                let inner = &after[..close];
                // Skip if it contains SELECT (subquery, not literal list)
                if inner.to_uppercase().contains("SELECT") { return Vec::new(); }
                let comma_count = inner.matches(',').count();
                if comma_count > 50 {
                    let msg = format!("IN clause with {} values - consider using temp table.", comma_count + 1);
                    return vec![self.build_issue(query, &msg, &query.raw[..query.raw.len().min(100)])];
                }
            }
        }
        Vec::new()
    }
}

struct UnboundedTempTableRule;
static PAT_TEMP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSELECT\b[^;]*\bINTO\s+[#@]\w+").unwrap());
impl Rule for UnboundedTempTableRule {
    fn id(&self) -> &'static str { "PERF-MEM-002" }
    fn name(&self) -> &'static str { "Unbounded Temp Table Creation" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Unbounded SELECT INTO can fill tempdb, crash the instance, or exhaust memory." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if let Some(m) = PAT_TEMP.find(&query.raw) {
            let upper = query.raw_upper();
            if upper.contains("WHERE") || upper.contains("TOP ") || upper.contains("LIMIT") {
                return Vec::new();
            }
            let msg = format!("Unbounded SELECT INTO temp table: {}", m.as_str());
            return vec![self.build_issue(query, &msg, m.as_str())];
        }
        Vec::new()
    }
}

struct GroupByHighCardinalityRule;
static HIGH_CARD_COLS: &[&str] = &[
    "timestamp", "datetime", "created_at", "updated_at", "modified_at",
    "uuid", "guid", "transaction_id", "session_id", "request_id",
    "email", "phone", "ip_address", "user_agent",
];
impl Rule for GroupByHighCardinalityRule {
    fn id(&self) -> &'static str { "PERF-MEM-004" }
    fn name(&self) -> &'static str { "GROUP BY on High-Cardinality Expression" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn impact(&self) -> &'static str { "Grouping by high-cardinality columns creates millions of groups, consuming massive memory." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("GROUP BY") { return Vec::new(); }
        let raw_lower = query.raw.to_lowercase();
        for col in HIGH_CARD_COLS {
            if raw_lower.contains(&format!("group by {}", col)) || raw_lower.contains(&format!("group by\n{}", col)) {
                let msg = format!("GROUP BY on high-cardinality column '{}' - may create excessive groups.", col);
                let snip = &query.raw[..query.raw.len().min(100)];
                return vec![self.build_issue(query, &msg, snip)];
            }
        }
        Vec::new()
    }
}

struct SelectIntoTempWithoutIndexRule;
impl Rule for SelectIntoTempWithoutIndexRule {
    fn id(&self) -> &'static str { "PERF-TSQL-002" }
    fn name(&self) -> &'static str { "SELECT INTO Temp Table Without Index" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Temp tables without indexes cause table scans on every join or filter." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("INTO #") { return Vec::new(); }
        if upper.contains("CREATE INDEX") || upper.contains("CREATE UNIQUE INDEX") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "SELECT INTO temp table without index - subsequent queries will table scan.", snip)]
    }
}

struct ImplicitConversionInJoinRule;
static PAT_CONV_JOIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\bJOIN\b.*\bCONVERT\s*\()|(\bCAST\s*\(.*\bJOIN\b)").unwrap());
impl Rule for ImplicitConversionInJoinRule {
    fn id(&self) -> &'static str { "PERF-TSQL-003" }
    fn name(&self) -> &'static str { "Implicit Conversion in JOIN Predicate" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfJoin) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Implicit conversion prevents index seeks, forcing table scans." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_CONV_JOIN.find(&query.raw).map(|m| {
            let msg = format!("Explicit CONVERT/CAST in JOIN predicate - check for implicit conversion: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LargeInClauseRule),
        Box::new(UnboundedTempTableRule),
        Box::new(GroupByHighCardinalityRule),
        Box::new(SelectIntoTempWithoutIndexRule),
        Box::new(ImplicitConversionInJoinRule),
        Box::new(OrderByWithoutLimitInSubqueryRule),
    ]
}

// PERF-MEM-003: ORDER BY Without LIMIT in Subquery
struct OrderByWithoutLimitInSubqueryRule;
static PAT_ORDER_SUB_NO_LIMIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\(\s*SELECT\b[^)]*\bORDER\s+BY\b").unwrap());
impl Rule for OrderByWithoutLimitInSubqueryRule {
    fn id(&self) -> &'static str { "PERF-MEM-003" }
    fn name(&self) -> &'static str { "ORDER BY Without LIMIT in Subquery" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfMemory) }
    fn impact(&self) -> &'static str { "Sorting without LIMIT in subqueries wastes resources." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_ORDER_SUB_NO_LIMIT.find(&query.raw) {
            let matched_upper = m.as_str().to_uppercase();
            if !matched_upper.contains("LIMIT") && !matched_upper.contains("TOP") {
                return vec![self.build_issue(query, "ORDER BY in subquery without LIMIT is meaningless and wastes resources.", m.as_str())];
            }
        }
        Vec::new()
    }
}
