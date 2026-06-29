use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

struct InsecureSessionTokenStorageRule;
static PAT_SESSION_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(session_token|auth_token|access_token|refresh_token|bearer_token|jwt_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?'?[A-Za-z0-9_\-\.]{20,}'?"#).unwrap()
});
impl Rule for InsecureSessionTokenStorageRule {
    fn id(&self) -> &'static str {
        "SEC-SESSION-001"
    }
    fn name(&self) -> &'static str {
        "Insecure Session Token Storage"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecSession)
    }
    fn impact(&self) -> &'static str {
        "Unhashed session tokens in databases can be stolen and replayed."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SESSION_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Insecure session token storage: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct SessionTimeoutNotEnforcedRule;
static PAT_SESSION_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bSELECT\b[^;]*\bFROM\s+\w*(session|token)s?\b[^;]*\bWHERE\b").unwrap()
});
impl Rule for SessionTimeoutNotEnforcedRule {
    fn id(&self) -> &'static str {
        "SEC-SESSION-002"
    }
    fn name(&self) -> &'static str {
        "Session Timeout Not Enforced"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecSession)
    }
    fn impact(&self) -> &'static str {
        "Sessions without expiration validation remain valid indefinitely. Stolen tokens provide permanent access."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_SESSION_002.find(&query.raw) {
            // Only flag when the query is clearly a session validation lookup.
            // Evidence: WHERE clause uses a token/session ID column for authentication.
            // If the query just reads from a sessions table with other filters
            // (e.g. user_id, status), it may not be a session validation query.
            let raw_lower = query.raw_lower().to_string();
            let has_expiry_check = [
                "expir",
                "valid_until",
                "expires_at",
                "ttl",
                "created_at",
                "last_activity",
                "timeout",
                "max_age",
            ]
            .iter()
            .any(|needle| raw_lower.contains(needle));
            if has_expiry_check {
                return Vec::new();
            }
            // Require that the WHERE clause actually filters by token/session_id
            // to confirm this is a session validation query, not just any read.
            let is_token_lookup = [
                "session_token",
                "session_id",
                "auth_token",
                "access_token",
                "refresh_token",
                "bearer_token",
                "token_hash",
            ]
            .iter()
            .any(|needle| raw_lower.contains(needle));
            if !is_token_lookup {
                return Vec::new();
            }
            return vec![self.build_issue(
                query,
                "Session validation query missing expiration check.",
                m.as_str(),
            )];
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(InsecureSessionTokenStorageRule),
        Box::new(SessionTimeoutNotEnforcedRule),
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

    fn q(sql: &str, dialect: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: dialect.to_string(),
            location: Location::new(1, 1),
            query_type: Some("INSERT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn session_001_fires_on_plaintext_token_insert() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-SESSION-001").unwrap();
        let sql =
            "INSERT INTO sessions (session_token) VALUES ('abcdefghijklmnopqrstuvwxyz1234567890')";
        let query = q(sql, "postgresql");
        let issues = rule.check(&query);
        assert!(!issues.is_empty(), "should flag plaintext token insert");
    }

    #[test]
    fn session_002_fires_on_token_lookup_without_expiry() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-SESSION-002").unwrap();
        let sql = "SELECT * FROM sessions WHERE session_token = :token";
        let query = Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        };
        let issues = rule.check(&query);
        assert!(
            !issues.is_empty(),
            "should flag token lookup without expiry check"
        );
    }

    #[test]
    fn session_002_no_fire_when_expiry_present() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-SESSION-002").unwrap();
        let sql = "SELECT * FROM sessions WHERE session_token = :token AND expires_at > NOW()";
        let query = Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        };
        let issues = rule.check(&query);
        assert!(
            issues.is_empty(),
            "should not flag when expiry check is present"
        );
    }

    #[test]
    fn session_002_no_fire_without_token_column_in_where() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-SESSION-002").unwrap();
        let sql = "SELECT * FROM sessions WHERE user_id = :user_id";
        let query = Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            query_type: Some("SELECT".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        };
        let issues = rule.check(&query);
        assert!(
            issues.is_empty(),
            "should not flag when WHERE does not use a token column"
        );
    }
}
