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
    fn confidence(&self) -> crate::rules::base::RuleConfidence {
        // Contextual: CREATE USER without password is valid for Unix socket auth
        // and localhost-only service accounts. Cannot prove insecurity from SQL alone.
        crate::rules::base::RuleConfidence::Contextual
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
    fn confidence(&self) -> crate::rules::base::RuleConfidence {
        // Contextual: GRANT ALL to localhost-only DBA accounts is standard practice.
        // Cannot prove excessive privilege from the SQL pattern alone.
        crate::rules::base::RuleConfidence::Contextual
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

    fn q(sql: &str, file: Option<&str>) -> Query {
        let mut location = Location::new(1, 1);
        if let Some(f) = file {
            location = location.with_file(f);
        }
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location,
            query_type: Some("CREATE".to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn auth_003_no_fire_with_restricted_account_flags() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-AUTH-003").unwrap();
        let query = q("CREATE USER app_user NOINHERIT", None);
        assert!(rule.check(&query).is_empty());
    }

    #[test]
    fn auth_003_no_fire_with_if_not_exists() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-AUTH-003").unwrap();
        let query = q("CREATE USER IF NOT EXISTS app_user", None);
        assert!(rule.check(&query).is_empty());
    }

    #[test]
    fn auth_005_no_fire_for_alter_default_privileges() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-AUTH-005").unwrap();
        let query = q(
            "ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO app_user",
            None,
        );
        assert!(rule.check(&query).is_empty());
    }

    #[test]
    fn auth_005_no_fire_for_scoped_grant_all_in_init_file() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-AUTH-005").unwrap();
        let query = q(
            "GRANT ALL ON TABLE users TO admin_user",
            Some("docker/init.sql"),
        );
        assert!(rule.check(&query).is_empty());
    }

    #[test]
    fn auth_005_scoped_grant_all_still_fires_outside_init_file() {
        let rules = rules();
        let rule = rules.iter().find(|r| r.id() == "SEC-AUTH-005").unwrap();
        let query = q("GRANT ALL ON TABLE users TO app_user", Some("src/app.sql"));
        assert!(!rule.check(&query).is_empty());
    }
}
