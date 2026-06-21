use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

// PERF-SCAN-001: SELECT *
struct SelectStarRule;
impl Rule for SelectStarRule {
    fn id(&self) -> &'static str {
        "PERF-SCAN-001"
    }
    fn name(&self) -> &'static str {
        "SELECT * Usage"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn impact(&self) -> &'static str {
        "Increases network traffic, memory usage, and prevents covering index usage."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        // In ad-hoc context (no file), SELECT * is expected for exploration
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if query.raw_upper().contains("SELECT *") {
            return vec![self.build_issue(
                query,
                "Avoid SELECT *, specify columns explicitly.",
                "SELECT *",
            )];
        }
        Vec::new()
    }
}

// PERF-SCAN-002: UPDATE/DELETE without WHERE
struct MissingWhereRule;
impl Rule for MissingWhereRule {
    fn id(&self) -> &'static str {
        "PERF-SCAN-002"
    }
    fn name(&self) -> &'static str {
        "Unbounded Data Modification"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn impact(&self) -> &'static str {
        "Will modify/delete ALL rows in the table, causing massive lock contention and log growth."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("");
        if qt != "UPDATE" && qt != "DELETE" {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("WHERE") {
            return Vec::new();
        }
        // Suppress intentional bulk operations (flush, clear, reset)
        if let Some(ref file) = query.location.file {
            let fl = file.to_lowercase();
            let filename = fl.rsplit('/').next().unwrap_or(&fl);
            if fl.contains("cache")
                || fl.contains("clear")
                || fl.contains("reset")
                || fl.contains("cleanup")
                || fl.contains("purge")
                || fl.contains("flush")
                || fl.contains("init.sql")
                || fl.contains("setup.sql")
                || fl.contains("teardown")
                || fl.contains("truncate")
                || filename.contains("flush")
                || filename.contains("clear")
                || filename.contains("reset")
                || filename.contains("purge")
                || filename.contains("testinfra")
                || filename.contains("sync")
            {
                return Vec::new();
            }
        }
        let msg = format!("Unbounded {} detected (missing WHERE).", qt);
        let snip = &query.raw[..query.raw.len().min(50)];
        vec![self.build_issue(query, &msg, snip)]
    }
}

// PERF-SCAN-003: SELECT without LIMIT
struct UnboundedSelectRule;
impl Rule for UnboundedSelectRule {
    fn id(&self) -> &'static str {
        "PERF-SCAN-003"
    }
    fn name(&self) -> &'static str {
        "Unbounded SELECT"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn impact(&self) -> &'static str {
        "May return millions of rows, overwhelming application memory."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        // In ad-hoc context, unbounded SELECT is normal exploration behavior.
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }

        if let Some(ref facts) = query.facts {
            if facts.has_limit {
                return Vec::new();
            }
            if facts.has_aggregation || facts.has_group_by {
                return Vec::new();
            }
            if facts.is_single_row_lookup() {
                return Vec::new();
            }
            if facts.has_where {
                return Vec::new();
            }
            // Skip constant expressions (SELECT 1, SELECT NOW())
            if facts.from_tables.is_empty() {
                return Vec::new();
            }
            // Skip system catalog queries
            if facts.from_tables.iter().any(|t| {
                let tl = t.to_lowercase();
                tl.starts_with("pg_")
                    || tl.starts_with("information_schema")
                    || tl.starts_with("sys.")
            }) {
                return Vec::new();
            }
        } else {
            let upper = query.raw_upper();
            if upper.contains("LIMIT") || upper.contains("TOP ") {
                return Vec::new();
            }
            if upper.contains("GROUP BY") || upper.contains("COUNT(") {
                return Vec::new();
            }
            if upper.contains("WHERE") {
                return Vec::new();
            }
            // Skip SELECT 1
            if !upper.contains("FROM") {
                return Vec::new();
            }
        }

        vec![self.build_issue(
            query,
            "SELECT without LIMIT on non-aggregated query.",
            query.snippet(80),
        )]
    }
}

// PERF-SCAN-004: NOT IN subquery
struct NotInSubqueryRule;
static PAT_NOT_IN_SUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bNOT\s+IN\s*\(\s*SELECT\b").unwrap());
impl Rule for NotInSubqueryRule {
    fn id(&self) -> &'static str {
        "PERF-SCAN-004"
    }
    fn name(&self) -> &'static str {
        "NOT IN Subquery"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn impact(&self) -> &'static str {
        "NOT IN with subquery fails silently with NULLs and disables index usage."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_NOT_IN_SUB
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "NOT IN with subquery detected. Vulnerable to NULL semantics.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-SCAN-005: DISTINCT
struct DistinctOnLargeSetRule;
static PAT_DISTINCT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSELECT\s+DISTINCT\b").unwrap());
impl Rule for DistinctOnLargeSetRule {
    fn id(&self) -> &'static str {
        "PERF-SCAN-005"
    }
    fn name(&self) -> &'static str {
        "Expensive DISTINCT"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn impact(&self) -> &'static str {
        "Requires sorting or hashing entire result set."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        PAT_DISTINCT
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "DISTINCT usage detected. Ensure this is necessary.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-PG-002: COUNT(*) without WHERE
struct CountStarWithoutWhereRule;
impl Rule for CountStarWithoutWhereRule {
    fn id(&self) -> &'static str {
        "PERF-PG-002"
    }
    fn name(&self) -> &'static str {
        "Unfiltered COUNT(*)"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "COUNT(*) on a large table without WHERE scans every row."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !query.is_select() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("COUNT(*)") && !upper.contains("COUNT( *)") {
            return Vec::new();
        }
        if upper.contains("WHERE") {
            return Vec::new();
        }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(
            query,
            "COUNT(*) without WHERE - consider pg_catalog.reltuples for approximate counts.",
            snip,
        )]
    }
}

// PERF-PG-003: NOT IN nullable subquery
struct NotInNullableSubqueryRule;
impl Rule for NotInNullableSubqueryRule {
    fn id(&self) -> &'static str {
        "PERF-PG-003"
    }
    fn name(&self) -> &'static str {
        "NOT IN With Potentially NULLable Subquery"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "A single NULL in the subquery result causes NOT IN to return zero rows."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !PAT_NOT_IN_SUB.is_match(&query.raw) {
            return Vec::new();
        }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "NOT IN with subquery may return wrong results if subquery contains NULLs - use NOT EXISTS.", snip)]
    }
}

// PERF-PG-004: SELECT FOR UPDATE without NOWAIT
struct SelectForUpdateWithoutNowaitPgRule;
impl Rule for SelectForUpdateWithoutNowaitPgRule {
    fn id(&self) -> &'static str {
        "PERF-PG-004"
    }
    fn name(&self) -> &'static str {
        "SELECT FOR UPDATE Without NOWAIT/SKIP LOCKED (PG)"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfLock)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "Without NOWAIT, the query blocks until the lock is released."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("FOR UPDATE") {
            return Vec::new();
        }
        if upper.contains("NOWAIT") || upper.contains("SKIP LOCKED") {
            return Vec::new();
        }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(
            query,
            "SELECT FOR UPDATE without NOWAIT or SKIP LOCKED - may block indefinitely.",
            snip,
        )]
    }
}

// PERF-MYSQL-001: SELECT FOR UPDATE without LIMIT
struct SelectForUpdateWithoutLimitMysqlRule;
impl Rule for SelectForUpdateWithoutLimitMysqlRule {
    fn id(&self) -> &'static str {
        "PERF-MYSQL-001"
    }
    fn name(&self) -> &'static str {
        "SELECT FOR UPDATE Without LIMIT (MySQL)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfLock)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "Locking too many rows blocks concurrent writes."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("FOR UPDATE") {
            return Vec::new();
        }
        if upper.contains("LIMIT") {
            return Vec::new();
        }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(
            query,
            "SELECT FOR UPDATE without LIMIT - may lock excessive rows in InnoDB.",
            snip,
        )]
    }
}

// PERF-MYSQL-002: ORDER BY RAND()
struct OrderByRandRule;
static PAT_RAND: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bORDER\s+BY\s+RAND\s*\(\s*\)").unwrap());
impl Rule for OrderByRandRule {
    fn id(&self) -> &'static str {
        "PERF-MYSQL-002"
    }
    fn name(&self) -> &'static str {
        "ORDER BY RAND() Full Table Sort"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfSort)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "On 1M rows, ORDER BY RAND() LIMIT 1 still reads and sorts all 1M rows."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_RAND
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "ORDER BY RAND() detected - full table sort regardless of LIMIT.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-MYSQL-003: FORCE INDEX
struct ForceIndexHintMysqlRule;
static PAT_FORCE_IDX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:FORCE|USE|IGNORE)\s+INDEX\s*\(").unwrap());
impl Rule for ForceIndexHintMysqlRule {
    fn id(&self) -> &'static str {
        "PERF-MYSQL-003"
    }
    fn name(&self) -> &'static str {
        "FORCE INDEX / USE INDEX Hint"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfHints)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "Forced indexes bypass the optimizer and may force worse plans over time."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_FORCE_IDX
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Index hint detected - may become suboptimal as data changes.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-BQ-001: DISTINCT on UNNEST
struct BigQueryDistinctOnUnnestRule;
static PAT_BQ_UNNEST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bSELECT\s+DISTINCT\b.*\bUNNEST\s*\(").unwrap());
impl Rule for BigQueryDistinctOnUnnestRule {
    fn id(&self) -> &'static str {
        "PERF-BQ-001"
    }
    fn name(&self) -> &'static str {
        "SELECT DISTINCT on UNNEST"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "UNNEST explodes arrays then DISTINCT shuffles all rows to deduplicate."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_BQ_UNNEST
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "DISTINCT on UNNEST - expensive full shuffle.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// PERF-BQ-002: REGEXP without WHERE
struct BigQueryRegexOnLargeTableRule;
static PAT_BQ_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bREGEXP_(?:CONTAINS|EXTRACT|REPLACE)\s*\(").unwrap());
impl Rule for BigQueryRegexOnLargeTableRule {
    fn id(&self) -> &'static str {
        "PERF-BQ-002"
    }
    fn name(&self) -> &'static str {
        "REGEXP on Large Table Without Filter"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfScan)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["bigquery"])
    }
    fn impact(&self) -> &'static str {
        "REGEXP on every row consumes slot time and increases cost."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_BQ_REGEX
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "REGEXP function detected - ensure WHERE clause limits scan.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SelectStarRule),
        Box::new(MissingWhereRule),
        Box::new(UnboundedSelectRule),
        Box::new(NotInSubqueryRule),
        Box::new(DistinctOnLargeSetRule),
        Box::new(CountStarWithoutWhereRule),
        Box::new(NotInNullableSubqueryRule),
        Box::new(SelectForUpdateWithoutNowaitPgRule),
        Box::new(SelectForUpdateWithoutLimitMysqlRule),
        Box::new(OrderByRandRule),
        Box::new(ForceIndexHintMysqlRule),
        Box::new(BigQueryDistinctOnUnnestRule),
        Box::new(BigQueryRegexOnLargeTableRule),
    ]
}
