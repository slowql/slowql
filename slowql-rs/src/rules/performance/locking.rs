use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct TableLockHintRule;
static PAT_LOCK_001: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWITH\s*\(\s*(TABLOCK|TABLOCKX|HOLDLOCK|XLOCK|PAGLOCK|ROWLOCK|UPDLOCK|SERIALIZABLE)\s*\)").unwrap());
impl Rule for TableLockHintRule {
    fn id(&self) -> &'static str { "PERF-LOCK-001" }
    fn name(&self) -> &'static str { "Table Lock Hint" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Table-level locks block ALL concurrent access to the table." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_LOCK_001.find(&query.raw).map(|m| {
            let msg = format!("Restrictive locking hint detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct ReadUncommittedHintRule;
static PAT_LOCK_002: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\bWITH\s*\(\s*(NOLOCK|READUNCOMMITTED)\s*\))|(\bREAD\s+UNCOMMITTED\b)|(\bSET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED\b)").unwrap());
impl Rule for ReadUncommittedHintRule {
    fn id(&self) -> &'static str { "PERF-LOCK-002" }
    fn name(&self) -> &'static str { "NOLOCK / Read Uncommitted Hint" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "NOLOCK reads uncommitted data, can skip rows, read rows twice, or return phantom data." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_LOCK_002.find(&query.raw).map(|m| {
            let msg = format!("NOLOCK or READ UNCOMMITTED hint detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct LongTransactionPatternRule;
static PAT_LOCK_003: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)\bBEGIN\s+(TRAN|TRANSACTION)\b[\s\S]{500,}?\b(COMMIT|ROLLBACK)\b").unwrap());
impl Rule for LongTransactionPatternRule {
    fn id(&self) -> &'static str { "PERF-LOCK-003" }
    fn name(&self) -> &'static str { "Long Transaction Pattern" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn impact(&self) -> &'static str { "Long transactions hold locks for their entire duration, blocking other queries." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_LOCK_003.find(&query.raw).map(|_| {
            vec![self.build_issue(query, "Potentially long-running transaction detected (500+ characters).", &query.raw[..query.raw.len().min(80)])]
        }).unwrap_or_default()
    }
}

struct MissingTransactionIsolationRule;
impl Rule for MissingTransactionIsolationRule {
    fn id(&self) -> &'static str { "PERF-LOCK-004" }
    fn name(&self) -> &'static str { "Missing Transaction Isolation Level" }
    fn severity(&self) -> Severity { Severity::Info }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn impact(&self) -> &'static str { "Default isolation levels vary by database and configuration." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        let has_begin = upper.contains("BEGIN TRAN") || upper.contains("BEGIN TRANSACTION");
        if has_begin && !upper.contains("ISOLATION LEVEL") {
            let snip = &query.raw[..query.raw.len().min(100)];
            return vec![self.build_issue(query, "Transaction without explicit isolation level.", snip)];
        }
        Vec::new()
    }
}

struct OracleForUpdateWithoutNowaitRule;
impl Rule for OracleForUpdateWithoutNowaitRule {
    fn id(&self) -> &'static str { "PERF-ORA-001" }
    fn name(&self) -> &'static str { "SELECT FOR UPDATE Without NOWAIT (Oracle)" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfLock) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["oracle"]) }
    fn impact(&self) -> &'static str { "Without NOWAIT, the session hangs waiting for row locks." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        let upper = query.raw_upper();
        if !upper.contains("FOR UPDATE") { return Vec::new(); }
        if upper.contains("NOWAIT") || upper.contains("SKIP LOCKED") || upper.contains("WAIT") { return Vec::new(); }
        let snip = &query.raw[..query.raw.len().min(80)];
        vec![self.build_issue(query, "SELECT FOR UPDATE without NOWAIT or SKIP LOCKED - may block indefinitely.", snip)]
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(TableLockHintRule),
        Box::new(ReadUncommittedHintRule),
        Box::new(LongTransactionPatternRule),
        Box::new(MissingTransactionIsolationRule),
        Box::new(OracleForUpdateWithoutNowaitRule),
    ]
}
