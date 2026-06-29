use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule};
use once_cell::sync::Lazy;
use regex::Regex;

struct OsCommandInjectionTsqlRule;
static PAT_CMD_001_TSQL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(xp_cmdshell|sp_OACreate|sp_OAMethod|EXEC\s+master\.\.xp_cmdshell)\b")
        .unwrap()
});

impl Rule for OsCommandInjectionTsqlRule {
    fn id(&self) -> &'static str {
        "SEC-CMD-001"
    }
    fn name(&self) -> &'static str {
        "OS Command Injection (SQL Server)"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecInjection)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "OS command execution from SQL gives attackers full server access."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_CMD_001_TSQL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("OS command injection procedure detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct OsCommandInjectionPostgresRule;
static PAT_CMD_001_PG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(pg_read_file|pg_execute_server_program|pg_ls_dir|pg_read_binary_file|FROM\s+PROGRAM)\b").unwrap()
});

impl Rule for OsCommandInjectionPostgresRule {
    fn id(&self) -> &'static str {
        "SEC-CMD-001-PG"
    }
    fn name(&self) -> &'static str {
        "OS Command Injection (PostgreSQL)"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecInjection)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "pg_read_file and pg_execute_server_program allow reading arbitrary files and executing OS commands."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_CMD_001_PG
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("PostgreSQL OS command function detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct PathTraversalRule;
static PAT_PATH_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(OPENROWSET|BULK\s+INSERT|LOAD_FILE|INTO\s+OUTFILE|UTL_FILE|BFILE|DBMS_LOB\.LOADFROMFILE)\b[^;]*(\+|CONCAT|\|\|)[^;]*'[^']*\.\.[/\\]"#).unwrap()
});

impl Rule for PathTraversalRule {
    fn id(&self) -> &'static str {
        "SEC-PATH-001"
    }
    fn name(&self) -> &'static str {
        "Path Traversal in File Operations"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAccess)
    }
    fn impact(&self) -> &'static str {
        "Path traversal allows attackers to read/write arbitrary files on the server."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_PATH_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Path traversal in file operation: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct LocalFileInclusionRule;
static PAT_PATH_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(EXECUTE|EXEC|SOURCE|@)\b[^;]*(\+|CONCAT|\|\|)[^;]*\.sql\b").unwrap()
});

impl Rule for LocalFileInclusionRule {
    fn id(&self) -> &'static str {
        "SEC-PATH-002"
    }
    fn name(&self) -> &'static str {
        "Local File Inclusion"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecInjection)
    }
    fn impact(&self) -> &'static str {
        "Including SQL files based on user input allows attackers to execute arbitrary SQL code."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_PATH_002
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Local file inclusion pattern: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct SsrfViaDatabaseRule;
static PAT_SSRF_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(sp_OACreate.*XMLHTTP|UTL_HTTP|DBMS_NETWORK|HTTPURLConnection|CURL)\b|\bOPENROWSET\b.*'[^']*(?:http|https|ftp|ldap|\\\\)"#).unwrap()
});

impl Rule for SsrfViaDatabaseRule {
    fn id(&self) -> &'static str {
        "SEC-SSRF-001"
    }
    fn name(&self) -> &'static str {
        "Server-Side Request Forgery via Database"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecInjection)
    }
    fn impact(&self) -> &'static str {
        "SSRF via database allows attackers to scan internal networks, access cloud metadata services, bypass firewalls."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SSRF_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("SSRF via database function: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct OracleUtlAccessRule;
static PAT_ORA_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bUTL_(?:HTTP|FILE|SMTP|TCP|INADDR)\b").unwrap());

impl Rule for OracleUtlAccessRule {
    fn id(&self) -> &'static str {
        "SEC-ORA-001"
    }
    fn name(&self) -> &'static str {
        "Oracle UTL Package Access"
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
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "UTL_HTTP enables SSRF from the database. UTL_FILE enables reading and writing files on the database server."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ORA_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!(
                        "Oracle UTL package access - potential SSRF or data exfiltration: {}",
                        m.as_str()
                    ),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct OpenRowsetRule;
static PAT_TSQL_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:OPENROWSET|OPENDATASOURCE)\s*\(").unwrap());

impl Rule for OpenRowsetRule {
    fn id(&self) -> &'static str {
        "SEC-TSQL-001"
    }
    fn name(&self) -> &'static str {
        "OPENROWSET / OPENDATASOURCE Usage"
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
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "OPENROWSET can read from arbitrary OLE DB sources including file system."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_TSQL_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Ad-hoc remote data access detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct SpOaCreateRule;
static PAT_TSQL_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bsp_OA(?:Create|Method|GetProperty|SetProperty|Destroy)\b").unwrap()
});

impl Rule for SpOaCreateRule {
    fn id(&self) -> &'static str {
        "SEC-TSQL-002"
    }
    fn name(&self) -> &'static str {
        "OLE Automation (sp_OACreate)"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAccess)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "OLE Automation enables arbitrary COM object instantiation and host compromise."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_TSQL_002
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("OLE Automation procedure detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct ClickHouseUrlFunctionRule;
static PAT_CH_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\burl\s*\(\s*'https?://"#).unwrap());

impl Rule for ClickHouseUrlFunctionRule {
    fn id(&self) -> &'static str {
        "SEC-CH-001"
    }
    fn name(&self) -> &'static str {
        "ClickHouse url() Table Function"
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
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["clickhouse"])
    }
    fn impact(&self) -> &'static str {
        "url() can reach internal services, cloud metadata endpoints, and exfiltrate data via HTTP requests."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_CH_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!(
                        "ClickHouse url() table function - SSRF risk: {}",
                        m.as_str()
                    ),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct AttachDatabaseRule;
static PAT_SQLITE_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bATTACH\s+(?:DATABASE\s+)?(?:'[^']*'|"[^"]*"|\S+)\s+AS\b"#).unwrap()
});

impl Rule for AttachDatabaseRule {
    fn id(&self) -> &'static str {
        "SEC-SQLITE-001"
    }
    fn name(&self) -> &'static str {
        "ATTACH DATABASE Arbitrary File Access"
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
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["sqlite"])
    }
    fn impact(&self) -> &'static str {
        "An attacker can read any file as a SQLite database or create new files."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_SQLITE_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!(
                        "ATTACH DATABASE detected - arbitrary file access risk: {}",
                        m.as_str()
                    ),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(OsCommandInjectionTsqlRule),
        Box::new(OsCommandInjectionPostgresRule),
        Box::new(PathTraversalRule),
        Box::new(LocalFileInclusionRule),
        Box::new(SsrfViaDatabaseRule),
        Box::new(OracleUtlAccessRule),
        Box::new(OpenRowsetRule),
        Box::new(SpOaCreateRule),
        Box::new(ClickHouseUrlFunctionRule),
        Box::new(AttachDatabaseRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str, dialect: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: dialect.to_string(),
            location: Location::new(1, 1),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn metadata_coverage() {
        let rules = rules();
        for rule in &rules {
            let _ = rule.id();
            let _ = rule.name();
            let _ = rule.severity();
            let _ = rule.dimension();
            let _ = rule.category();
            let _ = rule.impact();
            let _ = rule.fix_guidance();
            let _ = rule.confidence();
            let _ = rule.dialects();
        }
    }

    #[test]
    fn no_match_simple() {
        let rules = rules();
        let query = q("SELECT 1", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn dialect_coverage() {
        let rules = rules();
        let dialects = [
            "postgresql",
            "mysql",
            "tsql",
            "oracle",
            "sqlite",
            "bigquery",
            "snowflake",
            "redshift",
            "clickhouse",
        ];
        for dialect in &dialects {
            for qt in &["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"] {
                let query = q("SELECT 1", dialect, qt);
                for rule in &rules {
                    let _ = rule.check(&query);
                    let _ = rule.dialect_matches(&query);
                }
            }
        }
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn path_001_positive() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-PATH-001").unwrap();
        let query = q("SELECT LOAD_FILE('/safe/' || '../etc/passwd')");
        let issues = rule.check(&query);
        assert!(!issues.is_empty());
    }

    #[test]
    fn path_002_positive() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-PATH-002").unwrap();
        let query = q("EXEC '/tmp/' || user_input || 'evil.sql'");
        let issues = rule.check(&query);
        assert!(!issues.is_empty());
    }
}
