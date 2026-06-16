use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct LeadingWildcardRule;
static PAT_WILD: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\s+LIKE\s+['"]%[^'"]+['"]"#).unwrap());
impl Rule for LeadingWildcardRule {
    fn id(&self) -> &'static str { "PERF-IDX-002" }
    fn name(&self) -> &'static str { "Leading Wildcard Search" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "Leading wildcard prevents B-Tree index usage, forces full table scan." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_WILD.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "Non-SARGable query: Leading wildcard in LIKE clause.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct FunctionOnIndexedColumnRule;
static PAT_FUNC_WHERE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.*\b(LOWER|UPPER|TRIM|YEAR|MONTH|DAY|DATE|CAST|CONVERT|SUBSTRING|LEFT|RIGHT|REPLACE|COALESCE|ISNULL|NVL|IFNULL)\s*\(").unwrap());
impl Rule for FunctionOnIndexedColumnRule {
    fn id(&self) -> &'static str { "PERF-IDX-001" }
    fn name(&self) -> &'static str { "Function on Indexed Column" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "Prevents index usage, forces full table scan." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_FUNC_WHERE.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "Function applied to column in WHERE clause prevents index usage.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct ImplicitTypeConversionRule;
impl Rule for ImplicitTypeConversionRule {
    fn id(&self) -> &'static str { "PERF-IDX-003" }
    fn name(&self) -> &'static str { "Implicit Type Conversion on Indexed Column" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "Implicit type conversion turns index seeks into full scans." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Heuristic: numeric column name compared with string literal
        let raw_lower = query.raw.to_lowercase();
        let numeric_cols = ["_id ", "amount ", "quantity ", "price ", "count ", "total ", "age "];
        let has_numeric_col_with_string = numeric_cols.iter().any(|col| {
            if let Some(pos) = raw_lower.find(col) {
                let after = &raw_lower[pos..];
                after.contains("= '") || after.contains("='")
            } else { false }
        });
        if has_numeric_col_with_string {
            let snip = &query.raw[..query.raw.len().min(100)];
            return vec![self.build_issue(query, "Implicit type conversion: numeric column compared with string literal.", snip)];
        }
        Vec::new()
    }
}

struct OrOnIndexedColumnsRule;
static PAT_OR_WHERE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.+\bOR\b").unwrap());
impl Rule for OrOnIndexedColumnsRule {
    fn id(&self) -> &'static str { "PERF-IDX-004" }
    fn name(&self) -> &'static str { "OR in WHERE Clause" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "OR conditions can prevent index usage depending on the query planner." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_OR_WHERE.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "OR condition in WHERE clause detected.", m.as_str())]
        }).unwrap_or_default()
    }
}

struct DeepOffsetPaginationRule;
static PAT_OFFSET: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bOFFSET\s+([1-9]\d{3,})\b").unwrap());
impl Rule for DeepOffsetPaginationRule {
    fn id(&self) -> &'static str { "PERF-IDX-005" }
    fn name(&self) -> &'static str { "Deep Offset Pagination" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "Database must scan and discard all rows before the offset." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_OFFSET.find(&query.raw).map(|m| {
            let msg = format!("Deep pagination detected with large OFFSET: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct CoalesceOnIndexedColumnRule;
static PAT_COALESCE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.*\b(COALESCE|ISNULL|NVL|NVL2|IFNULL)\s*\(\s*\w+").unwrap());
impl Rule for CoalesceOnIndexedColumnRule {
    fn id(&self) -> &'static str { "PERF-IDX-008" }
    fn name(&self) -> &'static str { "COALESCE/ISNULL/NVL on Indexed Column" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn impact(&self) -> &'static str { "Wrapping a column in COALESCE/ISNULL forces evaluation of every row." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_COALESCE.find(&query.raw).map(|m| {
            let msg = format!("Function wrapping column in WHERE prevents index seek: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct IlikeOnIndexedColumnRule;
static PAT_ILIKE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bILIKE\b").unwrap());
impl Rule for IlikeOnIndexedColumnRule {
    fn id(&self) -> &'static str { "PERF-PG-001" }
    fn name(&self) -> &'static str { "ILIKE Disables Index" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfIndex) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) }
    fn impact(&self) -> &'static str { "ILIKE cannot use standard B-tree indexes, causes full table scans on large tables." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_ILIKE.find(&query.raw).map(|m| {
            vec![self.build_issue(query, "ILIKE detected - case-insensitive LIKE cannot use standard B-tree indexes.", m.as_str())]
        }).unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LeadingWildcardRule),
        Box::new(FunctionOnIndexedColumnRule),
        Box::new(ImplicitTypeConversionRule),
        Box::new(OrOnIndexedColumnsRule),
        Box::new(DeepOffsetPaginationRule),
        Box::new(CoalesceOnIndexedColumnRule),
        Box::new(IlikeOnIndexedColumnRule),
    ]
}
