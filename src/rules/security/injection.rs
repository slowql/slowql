use crate::models::issue::{Category, Fix};
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

// SEC-INJ-001
struct SqlInjectionRule;
static PAT_INJ_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(['"])\s*\+\s*[a-zA-Z_]\w*|[a-zA-Z_]\w*\s*\+\s*(['"])"#).unwrap()
});
impl Rule for SqlInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-001"
    }
    fn name(&self) -> &'static str {
        "Potential SQL Injection"
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
    fn impact(&self) -> &'static str {
        "Using string interpolation to build SQL queries is a primary source of SQL injection vulnerabilities."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let mut issues = Vec::new();
        if let Some(m) = PAT_INJ_001.find(&query.raw) {
            let msg = format!(
                "Potential SQL injection: string concatenation with variable '{}'",
                m.as_str()
            );
            issues.push(
                self.build_issue(query, &msg, m.as_str())
                    .with_fix(Fix::guidance(
                        "Use parameterized queries instead of string interpolation.",
                        self.id(),
                    )),
            );
        } else if query.is_dynamic {
            let snip = query.snippet(100);
            issues.push(
                self.build_issue(
                    query,
                    "Potential SQL injection: query is dynamically constructed.",
                    snip,
                )
                .with_fix(Fix::guidance(
                    "Use parameterized queries instead of string interpolation.",
                    self.id(),
                )),
            );
        }
        issues
    }
}

// SEC-INJ-002
struct DynamicSqlExecutionRule;
static PAT_INJ_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(EXEC\s*\()|(EXECUTE\s*\()|(EXECUTE\s+IMMEDIATE\b)|(sp_executesql\b)|(PREPARE\s+\w+\s+FROM\s+@)|(PREPARE\s+\w+\s+FROM\s+CONCAT\s*\()").unwrap()
});
impl Rule for DynamicSqlExecutionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-002"
    }
    fn name(&self) -> &'static str {
        "Dynamic SQL Execution"
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
        "Attackers can inject arbitrary SQL through unsanitized inputs passed into dynamically constructed queries."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_INJ_002.find(&query.raw) {
            // MySQL PREPARE stmt FROM @variable is native prepared statement
            // syntax, not dynamic SQL injection. Skip it.
            let upper = query.raw_upper();
            if upper.contains("PREPARE") && upper.contains("FROM @") {
                return Vec::new();
            }
            let msg = format!("Dynamic SQL execution detected: {}", m.as_str());
            return vec![self.build_issue(query, &msg, m.as_str())];
        }
        Vec::new()
    }
}

// SEC-INJ-003
struct TautologicalOrConditionRule;
static PAT_INJ_003: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bOR\s+1\s*=\s*1\b)|(\bOR\s+'[^']*'\s*=\s*'[^']*')|(\bOR\s+TRUE\b)").unwrap()
});
impl Rule for TautologicalOrConditionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-003"
    }
    fn name(&self) -> &'static str {
        "Tautological OR Condition"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecInjection)
    }
    fn impact(&self) -> &'static str {
        "Tautological OR conditions bypass authentication and authorization checks."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_003
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Tautological OR condition detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-004
struct TimeBasedBlindInjectionRule;
static PAT_INJ_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\bWAITFOR\s+DELAY\b)|(\bSLEEP\s*\()|(\bpg_sleep\s*\()|(\bBENCHMARK\s*\()")
        .unwrap()
});
impl Rule for TimeBasedBlindInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-004"
    }
    fn name(&self) -> &'static str {
        "Time-Based Blind Injection Indicator"
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
        "Blind SQL injection allows attackers to extract data one bit at a time by measuring response delays."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_004
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Time-based blind injection indicator: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-005
struct SecondOrderSqlInjectionRule;
static DANGEROUS_COLUMNS: &[&str] = &[
    "username",
    "user_name",
    "email",
    "name",
    "first_name",
    "last_name",
    "comment",
    "comments",
    "description",
    "title",
    "subject",
    "message",
    "address",
    "notes",
    "bio",
    "about",
    "query",
    "search",
    "filter",
    "filename",
    "filepath",
    "url",
    "callback",
    "redirect",
];

impl Rule for SecondOrderSqlInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-005"
    }
    fn name(&self) -> &'static str {
        "Second-Order SQL Injection Risk"
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
        "Data stored today may be concatenated into SQL tomorrow. Second-order injection bypasses input validation performed only at write time."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let qt = query.query_type.as_deref().unwrap_or("").to_uppercase();
        if qt != "INSERT" && qt != "UPDATE" {
            return Vec::new();
        }

        let raw_lower = query.raw_lower();
        let dangerous: Vec<&str> = DANGEROUS_COLUMNS
            .iter()
            .filter(|&&col| raw_lower.contains(col))
            .copied()
            .collect();

        if dangerous.is_empty() {
            return Vec::new();
        }

        // Precision fix:
        // Only flag if the write statement is dynamic or contains obvious concatenation.
        let raw = &query.raw;
        let has_concat = raw.contains("||") || raw.contains("CONCAT(") || raw.contains(" + ");
        if !query.is_dynamic && !has_concat {
            return Vec::new();
        }

        let msg = format!(
            "Storing user-controllable data in columns that risk second-order injection: {}",
            dangerous.join(", ")
        );
        vec![self
            .build_issue(query, &msg, query.snippet(100))
            .with_fix(Fix::guidance(
                "Parameterize all queries that retrieve and use stored data.",
                self.id(),
            ))]
    }
}

// SEC-INJ-007
struct LdapInjectionRule;
static PAT_INJ_007: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(LDAP|AD_|DIRECTORY)\w*\s*\([^)]*(\+|CONCAT|CONCATENATE|\|\|)[^)]*\b(cn=|ou=|dc=|uid=|objectClass=)\b").unwrap()
});
impl Rule for LdapInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-007"
    }
    fn name(&self) -> &'static str {
        "LDAP Injection in Directory Queries"
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_007
            .find(&query.raw)
            .map(|m| {
                let msg = format!("LDAP injection pattern: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-008
struct NoSqlInjectionRule;
static PAT_INJ_008: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(OPENJSON|JSON_QUERY|JSON_VALUE|FOR\s+JSON|MONGODB|COSMOSDB|mongo_\w*|json_\w*)\b[^;]*(\+|CONCAT|\|\|)[^;]*[{}\[\]$]").unwrap()
});
impl Rule for NoSqlInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-008"
    }
    fn name(&self) -> &'static str {
        "NoSQL Injection Pattern"
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_008
            .find(&query.raw)
            .map(|m| {
                let msg = format!("NoSQL injection pattern: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-009
struct XmlXPathInjectionRule;
static PAT_INJ_009: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(XMLQUERY|XMLEXISTS|XPATH|XQUERY|xml_)\b[^;]*(\+|CONCAT|\|\|)[^;]*[/\[\]]")
        .unwrap()
});
impl Rule for XmlXPathInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-009"
    }
    fn name(&self) -> &'static str {
        "XML/XPath Injection"
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_009
            .find(&query.raw)
            .map(|m| {
                let msg = format!("XML/XPath injection pattern: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-010
struct ServerSideTemplateInjectionRule;
static PAT_INJ_010: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(RENDER|TEMPLATE|EVAL|EXECUTE|PROCESS|render_)\w*\b\([^)]*(\+|CONCAT|\|\|)")
        .unwrap()
});
impl Rule for ServerSideTemplateInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-010"
    }
    fn name(&self) -> &'static str {
        "Server-Side Template Injection"
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_010
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Server-side template injection pattern: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-INJ-011
struct JsonFunctionInjectionRule;
static PAT_INJ_011: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(JSON_OBJECT|JSON_ARRAY|JSON_INSERT|JSON_REPLACE|JSON_SET|json_\w*)\b[^;]*(\+|CONCAT|\|\|)").unwrap()
});
impl Rule for JsonFunctionInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-INJ-011"
    }
    fn name(&self) -> &'static str {
        "SQL Injection via JSON Functions"
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_INJ_011
            .find(&query.raw)
            .map(|m| {
                let msg = format!("JSON function injection pattern: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-PG-003
struct RaiseNoticeInjectionRule;
static PAT_PG_003: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bRAISE\s+(?:NOTICE|WARNING|INFO|LOG|DEBUG)\s+.*\|\|").unwrap());
impl Rule for RaiseNoticeInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-PG-003"
    }
    fn name(&self) -> &'static str {
        "RAISE NOTICE Log Injection"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
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
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_PG_003
            .find(&query.raw)
            .map(|m| {
                let msg = format!(
                    "RAISE NOTICE with concatenation - log injection risk: {}",
                    m.as_str()
                );
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-ORA-002
struct OracleDbmsSqlInjectionRule;
static PAT_ORA_002: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bDBMS_SQL\s*\.\s*(?:PARSE|EXECUTE|OPEN_CURSOR)\b").unwrap());
impl Rule for OracleDbmsSqlInjectionRule {
    fn id(&self) -> &'static str {
        "SEC-ORA-002"
    }
    fn name(&self) -> &'static str {
        "DBMS_SQL Dynamic Execution"
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
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ORA_002
            .find(&query.raw)
            .map(|m| {
                let msg = format!("DBMS_SQL dynamic execution: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// SEC-ORA-003
struct OracleExecuteImmediateConcatRule;
static PAT_ORA_003: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bEXECUTE\s+IMMEDIATE\s+.*\|\|").unwrap());
impl Rule for OracleExecuteImmediateConcatRule {
    fn id(&self) -> &'static str {
        "SEC-ORA-003"
    }
    fn name(&self) -> &'static str {
        "EXECUTE IMMEDIATE With Concatenation"
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
        DialectSet::new(&["oracle"])
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ORA_003
            .find(&query.raw)
            .map(|m| {
                let msg = format!(
                    "EXECUTE IMMEDIATE with concatenation - SQL injection risk: {}",
                    m.as_str()
                );
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SqlInjectionRule),
        Box::new(DynamicSqlExecutionRule),
        Box::new(TautologicalOrConditionRule),
        Box::new(TimeBasedBlindInjectionRule),
        Box::new(SecondOrderSqlInjectionRule),
        Box::new(LdapInjectionRule),
        Box::new(NoSqlInjectionRule),
        Box::new(XmlXPathInjectionRule),
        Box::new(ServerSideTemplateInjectionRule),
        Box::new(JsonFunctionInjectionRule),
        Box::new(RaiseNoticeInjectionRule),
        Box::new(OracleDbmsSqlInjectionRule),
        Box::new(OracleExecuteImmediateConcatRule),
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
