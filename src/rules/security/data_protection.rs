use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct DataExfiltrationViaFileRule;
static PAT_DATA_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bINTO\s+OUTFILE\b)|(\bINTO\s+DUMPFILE\b)|(\bLOAD_FILE\s*\()|(\bLOAD\s+DATA\s+INFILE\b)|(\bBULK\s+INSERT\b)|(\bCOPY\b.+\bFROM\s+PROGRAM\b)|(\bCOPY\b.+\bTO\s+PROGRAM\b)").unwrap()
});
impl Rule for DataExfiltrationViaFileRule {
    fn id(&self) -> &'static str {
        "SEC-DATA-001"
    }
    fn name(&self) -> &'static str {
        "Data Exfiltration via File Operations"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDataExposure)
    }
    fn impact(&self) -> &'static str {
        "Attackers can export entire tables to attacker-readable locations or read sensitive OS files."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_DATA_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Data exfiltration via file operation: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct RemoteDataAccessRule;
static PAT_DATA_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bOPENROWSET\s*\()|(\bOPENDATASOURCE\s*\()|(\bOPENQUERY\s*\()|(\bdblink_connect\s*\()|(\bdblink_exec\s*\()|(\bdblink\s*\()").unwrap()
});
impl Rule for RemoteDataAccessRule {
    fn id(&self) -> &'static str {
        "SEC-DATA-002"
    }
    fn name(&self) -> &'static str {
        "Remote/Linked Data Access"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDataExposure)
    }
    fn impact(&self) -> &'static str {
        "Attackers can use remote access functions to exfiltrate data to external servers or pivot to other databases."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_DATA_002
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Remote data access detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct LoadDataLocalInfileRule;
static PAT_MYSQL_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bLOAD\s+DATA\s+LOCAL\s+INFILE\b").unwrap());
impl Rule for LoadDataLocalInfileRule {
    fn id(&self) -> &'static str {
        "SEC-MYSQL-001"
    }
    fn name(&self) -> &'static str {
        "LOAD DATA LOCAL INFILE"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDataExposure)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "A rogue MySQL server can read any file the client has access to."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_MYSQL_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!(
                    "LOAD DATA LOCAL INFILE detected - client file read risk: {}",
                    m.as_str()
                );
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct RedshiftCopyWithCredentialsRule;
static PAT_RS_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bCOPY\b.*\b(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|CREDENTIALS)\b").unwrap()
});
impl Rule for RedshiftCopyWithCredentialsRule {
    fn id(&self) -> &'static str {
        "SEC-RS-001"
    }
    fn name(&self) -> &'static str {
        "COPY With Embedded Credentials"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDataExposure)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["redshift"])
    }
    fn impact(&self) -> &'static str {
        "AWS credentials in SQL appear in pg_stat_activity, query logs, STL_QUERYTEXT."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_RS_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!(
                    "COPY with embedded credentials - credential exposure risk: {}",
                    m.as_str()
                );
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct SnowflakeCopyWithCredentialsRule;
static PAT_SF_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\bCOPY\s+INTO\b.*\b(?:AWS_KEY_ID|AWS_SECRET_KEY|AZURE_SAS_TOKEN|CREDENTIALS)\b",
    )
    .unwrap()
});
impl Rule for SnowflakeCopyWithCredentialsRule {
    fn id(&self) -> &'static str {
        "SEC-SF-001"
    }
    fn name(&self) -> &'static str {
        "COPY INTO With Embedded Credentials"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecDataExposure)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "Cloud credentials appear in QUERY_HISTORY, INFORMATION_SCHEMA, and Snowflake audit logs."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_SF_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!(
                    "COPY INTO with embedded credentials - credential exposure risk: {}",
                    m.as_str()
                );
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct SnowflakeCloneWithoutCopyGrantsRule;
static PAT_SF_002: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCLONE\b").unwrap());
impl Rule for SnowflakeCloneWithoutCopyGrantsRule {
    fn id(&self) -> &'static str {
        "SEC-SF-002"
    }
    fn name(&self) -> &'static str {
        "CLONE Without COPY GRANTS"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAccess)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "The cloned object inherits default role permissions instead of the source grants."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_SF_002.find(&query.raw) {
            let raw_upper = query.raw.to_uppercase();
            if !raw_upper.contains("COPY GRANTS") {
                let msg = format!(
                    "CLONE without COPY GRANTS - permissions not preserved: {}",
                    m.as_str()
                );
                return vec![self.build_issue(query, &msg, m.as_str())];
            }
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DataExfiltrationViaFileRule),
        Box::new(RemoteDataAccessRule),
        Box::new(LoadDataLocalInfileRule),
        Box::new(RedshiftCopyWithCredentialsRule),
        Box::new(SnowflakeCopyWithCredentialsRule),
        Box::new(SnowflakeCloneWithoutCopyGrantsRule),
    ]
}
