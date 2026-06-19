use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{RuleConfidence, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct DatabaseVersionDisclosureRule;
static PAT_INFO_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)@@VERSION|VERSION\(\)|SERVERPROPERTY\('ProductVersion'\)|pg_version\(\)|BANNER|v\$version").unwrap()
});

impl Rule for DatabaseVersionDisclosureRule {
    fn id(&self) -> &'static str { "SEC-INFO-001" }
    fn name(&self) -> &'static str { "Database Version Disclosure" }
    fn severity(&self) -> Severity { Severity::Low }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDataExposure) }
    fn impact(&self) -> &'static str { "Exposing database version helps attackers identify known vulnerabilities (CVEs) specific to that version." }


    fn confidence(&self) -> RuleConfidence { RuleConfidence::Advisory }
    fn check(&self, query: &Query) -> Vec<Issue> { if query.source_context == "adhoc" || query.source_context.is_empty() { return Vec::new(); } PAT_INFO_001.find(&query.raw).map(|m| { let msg = format!("Database version disclosure: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

struct SchemaInformationDisclosureRule;
static PAT_INFO_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(INFORMATION_SCHEMA|sys\.|pg_catalog|ALL_TABLES|USER_TABLES|DBA_TABLES|SHOW\s+TABLES|SHOW\s+COLUMNS|DESCRIBE|syscolumns|sysobjects)\b").unwrap()
});

impl Rule for SchemaInformationDisclosureRule {
    fn id(&self) -> &'static str { "SEC-INFO-002" }
    fn name(&self) -> &'static str { "Schema Information Disclosure" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDataExposure) }
    fn impact(&self) -> &'static str { "Schema enumeration reveals table names, column names, and relationships. Attackers use this for targeted SQL injection." }


    fn confidence(&self) -> RuleConfidence { RuleConfidence::Contextual }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() { return Vec::new(); }
        if !PAT_INFO_002.is_match(&query.raw) { return Vec::new(); }
        // ORM introspection modules legitimately query schema metadata.
        // Skip when the file path indicates this is an adapter/introspection layer.
        if let Some(ref file) = query.location.file {
            let fl = file.to_lowercase();
            if fl.contains("introspection") || fl.contains("adapter")
                || fl.contains("backend") || fl.contains("connection_adapter")
                || fl.contains("schema_statements") {
                return Vec::new();
            }
        }
        // Legitimate uses: ORM introspection, migration tools, admin dashboards.
        // Only flag when there is evidence of dynamic enumeration or injection context:
        // concatenation, dynamic SQL, or UNION-based extraction pattern.
        let has_dynamic_signal = query.raw.contains("||")
            || query.raw.contains("CONCAT(")
            || query.raw.contains(" + ")
            || query.is_dynamic
            || query.raw_upper().contains("UNION")
            || query.raw_upper().contains("EXEC(")
            || query.raw_upper().contains("EXECUTE(");
        if !has_dynamic_signal { return Vec::new(); }
        PAT_INFO_002.find(&query.raw).map(|m| {
            let msg = format!("Schema information disclosure: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    } }

struct TimingAttackPatternRule;
static PAT_INFO_003: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(SLEEP|WAITFOR\s+DELAY|DBMS_LOCK\.SLEEP|PG_SLEEP)\b\s*\(\s*\d+\s*\)").unwrap()
});

impl Rule for TimingAttackPatternRule {
    fn id(&self) -> &'static str { "SEC-INFO-003" }
    fn name(&self) -> &'static str { "Timing Attack Pattern" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDataExposure) }
    fn impact(&self) -> &'static str { "Attackers can infer password characters through timing analysis." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INFO_003.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("Timing attack pattern detected: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

struct VerboseErrorMessageDisclosureRule;
static PAT_INFO_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(RAISERROR|THROW|SIGNAL)\b[^;]*\b(@@ERROR|ERROR_MESSAGE|SQLERRM|SQLSTATE)|\bCAST\s*\(\s*(?:@@VERSION|VERSION\(\)|BANNER)").unwrap()
});

impl Rule for VerboseErrorMessageDisclosureRule {
    fn id(&self) -> &'static str { "SEC-INFO-004" }
    fn name(&self) -> &'static str { "Verbose Error Messages" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecDataExposure) }
    fn impact(&self) -> &'static str { "Error messages containing schema names or query fragments help attackers understand database structure." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INFO_004.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("Verbose error message disclosure: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DatabaseVersionDisclosureRule),
        Box::new(SchemaInformationDisclosureRule),
        Box::new(TimingAttackPatternRule),
        Box::new(VerboseErrorMessageDisclosureRule),
    ]
}
