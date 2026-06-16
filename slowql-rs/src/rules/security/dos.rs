use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct UnboundedRecursiveCteRule;
static PAT_DOS_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bWITH\s+RECURSIVE\b|\bWITH\b[\s\S]*?\bUNION\s+ALL\b").unwrap()
});

impl Rule for UnboundedRecursiveCteRule {
    fn id(&self) -> &'static str { "SEC-DOS-001" }
    fn name(&self) -> &'static str { "Unbounded Recursive CTE" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDos) }
    fn impact(&self) -> &'static str { "Unbounded recursion can consume all available memory and CPU, crashing the database server." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !PAT_DOS_001.is_match(&query.raw) { return Vec::new(); }
        let raw_upper = query.raw_upper();
        if raw_upper.contains("MAXRECURSION") { return Vec::new(); }
        vec![self.build_issue(
            query,
            "Recursive CTE without MAXRECURSION limit - unbounded recursion risk",
            &query.raw[..query.raw.len().min(100)],
        )]
    }
}

struct RegexDenialOfServiceRule;
static PAT_DOS_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(REGEXP|RLIKE|REGEXP_LIKE|REGEXP_MATCHES|SIMILAR\s+TO)\s*\(?[^)]*(\(\?\:?\[?\w+\]\*\)[\*\+]|\(\.\*\)[\*\+]|\(\w\+\)[\*\+]|\[\^?\w+\]\*\[\^?\w+\]\*)").unwrap()
});

impl Rule for RegexDenialOfServiceRule {
    fn id(&self) -> &'static str { "SEC-DOS-002" }
    fn name(&self) -> &'static str { "Regex Denial of Service (ReDoS)" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDos) }
    fn impact(&self) -> &'static str { "ReDoS patterns like (a+)+ can take exponential time on crafted input, hanging database threads for hours." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_DOS_002.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("Potential ReDoS pattern detected: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

struct PgSleepUsageRule;
static PAT_PG_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bpg_sleep\s*\(").unwrap()
});

impl Rule for PgSleepUsageRule {
    fn id(&self) -> &'static str { "SEC-PG-001" }
    fn name(&self) -> &'static str { "pg_sleep Usage Detected" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDos) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) }
    fn impact(&self) -> &'static str { "pg_sleep() ties up a database connection and can exhaust the connection pool, causing denial of service." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_PG_001.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("pg_sleep() call detected - potential DoS vector: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

struct TsqlWaitforDelayRule;
static PAT_TSQL_WAIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bWAITFOR\s+DELAY\b").unwrap()
});

impl Rule for TsqlWaitforDelayRule {
    fn id(&self) -> &'static str { "PERF-TSQL-004" }
    fn name(&self) -> &'static str { "WAITFOR DELAY in Production Code" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Performance }
    fn category(&self) -> Option<Category> { Some(Category::PerfExecution) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "WAITFOR DELAY ties up a connection and worker thread, exhausting the connection pool under load." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_TSQL_WAIT.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("WAITFOR DELAY detected - testing artifact or blind injection vector: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnboundedRecursiveCteRule),
        Box::new(RegexDenialOfServiceRule),
        Box::new(PgSleepUsageRule),
        Box::new(TsqlWaitforDelayRule),
    ]
}
