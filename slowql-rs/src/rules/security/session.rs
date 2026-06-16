use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct InsecureSessionTokenStorageRule;
static PAT_SESSION_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(session_token|auth_token|access_token|refresh_token|bearer_token|jwt_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?'?[A-Za-z0-9_\-\.]{20,}'?"#).unwrap()
});
impl Rule for InsecureSessionTokenStorageRule {
    fn id(&self) -> &'static str { "SEC-SESSION-001" }
    fn name(&self) -> &'static str { "Insecure Session Token Storage" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecSession) }
    fn impact(&self) -> &'static str { "Unhashed session tokens in databases can be stolen and replayed." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_SESSION_001.find(&query.raw).map(|m| {
            let msg = format!("Insecure session token storage: {}", m.as_str());
            vec![self.build_issue(query, &msg, m.as_str())]
        }).unwrap_or_default()
    }
}

struct SessionTimeoutNotEnforcedRule;
static PAT_SESSION_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bSELECT\b[^;]*\bFROM\s+\w*(session|token)s?\b[^;]*\bWHERE\b").unwrap()
});
impl Rule for SessionTimeoutNotEnforcedRule {
    fn id(&self) -> &'static str { "SEC-SESSION-002" }
    fn name(&self) -> &'static str { "Session Timeout Not Enforced" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecSession) }
    fn impact(&self) -> &'static str { "Sessions without expiration validation remain valid indefinitely. Stolen tokens provide permanent access." }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_SESSION_002.find(&query.raw) {
            let raw_lower = query.raw_lower().to_string();
            let has_expiry_check = ["expir", "valid_until", "expires_at", "ttl", "created_at"]
                .iter()
                .any(|needle| raw_lower.contains(needle));
            if !has_expiry_check {
                return vec![self.build_issue(query, "Session validation query missing expiration check", m.as_str())];
            }
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
