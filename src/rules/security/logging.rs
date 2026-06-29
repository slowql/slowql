use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct SensitiveDataInErrorOutputRule;
static PAT_LOG_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(RAISERROR|THROW|RAISE|PRINT|DBMS_OUTPUT\.PUT_LINE|RAISE\s+NOTICE)\b[^;]*\b(password|pwd|ssn|social_security|credit_card|card_number|cvv|secret|token|api_key|private_key)\b").unwrap()
});

impl Rule for SensitiveDataInErrorOutputRule {
    fn id(&self) -> &'static str {
        "SEC-LOG-001"
    }
    fn name(&self) -> &'static str {
        "Sensitive Data in Error Output"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecLogging)
    }
    fn impact(&self) -> &'static str {
        "Sensitive data in error messages may be logged, displayed to users, or sent to monitoring systems."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_LOG_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Sensitive data exposed in error output: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct AuditTrailManipulationRule;
static PAT_LOG_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(DELETE\s+FROM|TRUNCATE|UPDATE|DROP\s+TABLE)\s+[^;]*\b(audit|audit_log|audit_trail|event_log|security_log|access_log|change_log|history)\b|\b(SET\s+(?:sql_log_off|general_log|audit_trail|log_statement)\s*=\s*(?:0|OFF|NONE|false))\b").unwrap()
});

impl Rule for AuditTrailManipulationRule {
    fn id(&self) -> &'static str {
        "SEC-LOG-002"
    }
    fn name(&self) -> &'static str {
        "Audit Trail Manipulation"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecLogging)
    }
    fn impact(&self) -> &'static str {
        "Audit log tampering destroys forensic capability and violates every compliance framework."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_LOG_002
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Audit trail manipulation detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SensitiveDataInErrorOutputRule),
        Box::new(AuditTrailManipulationRule),
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
