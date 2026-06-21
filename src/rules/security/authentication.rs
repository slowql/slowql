use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct HardcodedPasswordRule;
static PAT_AUTH_001: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(password|passwd|pwd|secret|token)\s*=\s*'[^']+'").unwrap());
impl Rule for HardcodedPasswordRule {
    fn id(&self) -> &'static str {
        "SEC-AUTH-001"
    }
    fn name(&self) -> &'static str {
        "Hardcoded Password"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAuthentication)
    }
    fn impact(&self) -> &'static str {
        "Credentials exposed in source code or logs can be used by attackers."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTH_001
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Hardcoded credential detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct GrantToPublicRule;
static PAT_AUTH_002: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bGRANT\b.+\bTO\s+PUBLIC\b").unwrap());
impl Rule for GrantToPublicRule {
    fn id(&self) -> &'static str {
        "SEC-AUTH-002"
    }
    fn name(&self) -> &'static str {
        "Grant to PUBLIC Role"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAuthentication)
    }
    fn impact(&self) -> &'static str {
        "Granting permissions to PUBLIC gives every current and future database user access."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTH_002
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Grant to PUBLIC role detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

// No look-ahead: match CREATE USER/LOGIN then check absence of password clause via string search
struct UserCreationWithoutPasswordRule;
static PAT_AUTH_003: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+(USER|LOGIN)\b").unwrap());
static PAT_HAS_PASSWORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(IDENTIFIED\s+BY|WITH\s+PASSWORD|PASSWORD\s*=)").unwrap());
impl Rule for UserCreationWithoutPasswordRule {
    fn id(&self) -> &'static str {
        "SEC-AUTH-003"
    }
    fn name(&self) -> &'static str {
        "User Creation Without Password"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAuthentication)
    }
    fn impact(&self) -> &'static str {
        "Passwordless database accounts can be accessed by anyone who knows the username."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(m) = PAT_AUTH_003.find(&query.raw) {
            if PAT_HAS_PASSWORD.is_match(&query.raw) {
                return Vec::new();
            }
            let upper = query.raw_upper();
            // Suppress when CREATE USER has security restrictions applied.
            // PostgreSQL: NOINHERIT, NOREPLICATION, LOGIN NOREPLICATION etc.
            // These indicate a deliberately restricted service account, not a
            // passwordless user accessible to anyone.
            if upper.contains("NOINHERIT")
                || upper.contains("NOREPLICATION")
                || upper.contains("NOSUPERUSER")
                || upper.contains("NOCREATEDB")
            {
                return Vec::new();
            }
            // Suppress when guarded by IF NOT EXISTS check
            if upper.contains("IF NOT EXISTS") {
                return Vec::new();
            }
            let msg = format!("User/login created without password: {}", m.as_str());
            return vec![self.build_issue(query, &msg, m.as_str())];
        }
        Vec::new()
    }
}

struct PasswordPolicyBypassRule;
static PAT_AUTH_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(CHECK_POLICY\s*=\s*OFF\b)|(CHECK_EXPIRATION\s*=\s*OFF\b)").unwrap()
});
impl Rule for PasswordPolicyBypassRule {
    fn id(&self) -> &'static str {
        "SEC-AUTH-004"
    }
    fn name(&self) -> &'static str {
        "Password Policy Bypass"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAuthentication)
    }
    fn impact(&self) -> &'static str {
        "Weak passwords without policy enforcement are vulnerable to brute force and credential stuffing attacks."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTH_004
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Password policy bypass detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct GrantAllRule;
static PAT_AUTH_005: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bGRANT\s+ALL\b").unwrap());
impl Rule for GrantAllRule {
    fn id(&self) -> &'static str {
        "SEC-AUTH-005"
    }
    fn name(&self) -> &'static str {
        "Excessive Privileges (GRANT ALL)"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecAuthentication)
    }
    fn impact(&self) -> &'static str {
        "Users receive administrative control, increasing blast radius of compromise."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !PAT_AUTH_005.is_match(&query.raw) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        // Suppress scoped GRANT ALL: when privileges are limited to a specific
        // schema, table, or function, this is a deliberate admin setup pattern.
        // Only flag unscoped GRANT ALL that gives broad access.
        // ALTER DEFAULT PRIVILEGES ... GRANT ALL is always scoped by definition.
        if upper.contains("ALTER DEFAULT PRIVILEGES") {
            return Vec::new();
        }
        if upper.contains("ON SCHEMA ")
            || upper.contains("ON TABLE ")
            || upper.contains("ON FUNCTION ")
            || upper.contains("ON SEQUENCE ")
            || upper.contains("ON ALL TABLES IN SCHEMA ")
            || upper.contains("ON ALL FUNCTIONS IN SCHEMA ")
            || upper.contains("ON ALL SEQUENCES IN SCHEMA ")
        {
            // Scoped to specific object or schema - check if it is a dedicated admin user
            // by looking at the file context
            if let Some(ref file) = query.location.file {
                let fl = file.to_lowercase();
                if fl.contains("init")
                    || fl.contains("setup")
                    || fl.contains("docker")
                    || fl.contains("bootstrap")
                    || fl.contains("provision")
                {
                    return Vec::new();
                }
            }
        }
        PAT_AUTH_005
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "GRANT ALL detected. Follow principle of least privilege.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HardcodedPasswordRule),
        Box::new(GrantToPublicRule),
        Box::new(UserCreationWithoutPasswordRule),
        Box::new(PasswordPolicyBypassRule),
        Box::new(GrantAllRule),
    ]
}
