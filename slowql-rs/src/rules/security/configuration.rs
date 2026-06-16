use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct DangerousServerConfigRule;
static PAT_CFG_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bsp_configure\b.+\bxp_cmdshell\b)|(\bsp_configure\b.+\bOle\s+Automation\b)|(\bsp_configure\b.+\bclr\s+enabled\b)|(\bsp_configure\b.+\bAd\s+Hoc\s+Distributed\s+Queries\b)").unwrap()
});
impl Rule for DangerousServerConfigRule {
    fn id(&self) -> &'static str { "SEC-CFG-001" }
    fn name(&self) -> &'static str { "Dangerous Server Configuration" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAccess) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["tsql"]) }
    fn impact(&self) -> &'static str { "Enabling xp_cmdshell gives SQL users full operating system command execution." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_CFG_001.find(&query.raw).map(|m| {
            let msg = format!("Dangerous server configuration detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct OverprivilegedExecutionContextRule;
static PAT_PRIV_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bEXECUTE\s+AS\s+(USER\s*=\s*)?'(dbo|sa|sysadmin)')|(\bEXECUTE\s+AS\s+(OWNER|SELF)\b)|(\bSECURITY\s+DEFINER\b)|(\bWITH\s+ADMIN\s+OPTION\b)|(\bWITH\s+GRANT\s+OPTION\b)").unwrap()
});
impl Rule for OverprivilegedExecutionContextRule {
    fn id(&self) -> &'static str { "SEC-PRIV-001" }
    fn name(&self) -> &'static str { "Overprivileged Execution Context" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthentication) }
    fn impact(&self) -> &'static str { "Stored procedures running as high-privilege accounts can be exploited for privilege escalation." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_PRIV_001.find(&query.raw).map(|m| {
            let msg = format!("Overprivileged execution context detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct HardcodedCredentialsRule;
static PAT_CONFIG_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(PASSWORD\s*=\s*'[^']{4,}'|pwd\s*=\s*'[^']{4,}'|IDENTIFIED\s+BY\s+'[^']+')"#).unwrap()
});
impl Rule for HardcodedCredentialsRule {
    fn id(&self) -> &'static str { "SEC-CONFIG-001" }
    fn name(&self) -> &'static str { "Hardcoded Database Credentials" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthentication) }
    fn impact(&self) -> &'static str { "Hardcoded credentials in queries are stored in query logs, execution history, source control, and backups." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CONFIG_001.find(&query.raw).map(|m| {
            let msg = format!("Hardcoded database credentials detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct WeakSslConfigRule;
static PAT_CONFIG_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(Encrypt\s*=\s*(false|no|0)|TrustServerCertificate\s*=\s*true|sslmode\s*=\s*(disable|allow|prefer)|ssl\s*=\s*(false|0))").unwrap()
});
impl Rule for WeakSslConfigRule {
    fn id(&self) -> &'static str { "SEC-CONFIG-002" }
    fn name(&self) -> &'static str { "Weak SSL/TLS Configuration" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthentication) }
    fn impact(&self) -> &'static str { "Disabling SSL/TLS exposes all data in transit to interception." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CONFIG_002.find(&query.raw).map(|m| {
            let msg = format!("Weak SSL/TLS configuration: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct DefaultCredentialUsageRule;
static PAT_CONFIG_003: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(sa|admin|root|postgres|mysql)\b.*\b(Password\s*=\s*'?(sa|admin|root|password|123456|default)'?|IDENTIFIED\s+BY\s+'?(sa|admin|root|password)'?)"#).unwrap()
});
impl Rule for DefaultCredentialUsageRule {
    fn id(&self) -> &'static str { "SEC-CONFIG-003" }
    fn name(&self) -> &'static str { "Default Credential Usage" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthentication) }
    fn impact(&self) -> &'static str { "Default credentials are the #1 cause of database breaches." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CONFIG_003.find(&query.raw).map(|m| {
            let msg = format!("Default credential usage detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct OverlyPermissiveAccessRule;
static PAT_CONFIG_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(GRANT\s+.*\s+TO\s+.*@'%'|CREATE\s+USER\s+.*@'%'|Host\s*=\s*'?(\*|0\.0\.0\.0|%|::|all)'?)"#).unwrap()
});
impl Rule for OverlyPermissiveAccessRule {
    fn id(&self) -> &'static str { "SEC-CONFIG-004" }
    fn name(&self) -> &'static str { "Overly Permissive CORS/Access" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthentication) }
    fn impact(&self) -> &'static str { "Allowing connections from any host exposes database to internet-wide attacks." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CONFIG_004.find(&query.raw).map(|m| {
            let msg = format!("Overly permissive access configuration: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct SearchPathManipulationRule;
static PAT_PG_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bSET\s+search_path\b").unwrap()
});
impl Rule for SearchPathManipulationRule {
    fn id(&self) -> &'static str { "SEC-PG-002" }
    fn name(&self) -> &'static str { "Search Path Manipulation" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAccess) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) }
    fn impact(&self) -> &'static str { "An attacker who can SET search_path can place a trojan function or table in a schema earlier in the path." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        PAT_PG_002.find(&query.raw).map(|m| {
            let msg = format!("search_path manipulation detected: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct PgSecurityDefinerWithoutSearchPathRule;
static PAT_PG_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bSECURITY\s+DEFINER\b").unwrap()
});
impl Rule for PgSecurityDefinerWithoutSearchPathRule {
    fn id(&self) -> &'static str { "SEC-PG-004" }
    fn name(&self) -> &'static str { "SECURITY DEFINER Without search_path" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAccess) }
    fn dialects(&self) -> DialectSet { DialectSet::new(&["postgresql"]) }
    fn impact(&self) -> &'static str { "An attacker can hijack unqualified object references by manipulating the caller search_path." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) { return Vec::new(); }
        if let Some(m) = PAT_PG_004.find(&query.raw) {
            let raw_upper = query.raw.to_uppercase();
            if !raw_upper.contains("SEARCH_PATH") {
                let msg = format!("SECURITY DEFINER without SET search_path - privilege escalation risk: {}", m.as_str());
                return vec![self.build_issue(query, &msg, m.as_str())];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DangerousServerConfigRule),
        Box::new(OverprivilegedExecutionContextRule),
        Box::new(HardcodedCredentialsRule),
        Box::new(WeakSslConfigRule),
        Box::new(DefaultCredentialUsageRule),
        Box::new(OverlyPermissiveAccessRule),
        Box::new(SearchPathManipulationRule),
        Box::new(PgSecurityDefinerWithoutSearchPathRule),
    ]
}
