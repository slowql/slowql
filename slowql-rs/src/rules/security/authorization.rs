use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct PrivilegeEscalationRoleGrantRule;
static PAT_AUTHZ_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(GRANT|ALTER\s+ROLE|sp_addrolemember|ALTER\s+USER)\b[^;]+\b(admin|administrator|superuser|sysadmin|db_owner|dba|root|securityadmin|serveradmin|dbcreator|sa)\b").unwrap()
});

impl Rule for PrivilegeEscalationRoleGrantRule {
    fn id(&self) -> &'static str { "SEC-AUTHZ-001" }
    fn name(&self) -> &'static str { "Privilege Escalation via Role Grant" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthorization) }
    fn impact(&self) -> &'static str { "Unrestricted admin access enables total database compromise." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTHZ_001.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("High-privilege role grant detected: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

struct SchemaOwnershipChangeRule;
static PAT_AUTHZ_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(ALTER\s+AUTHORIZATION\s+ON|ALTER\s+SCHEMA\s+\w+\s+TRANSFER|CHOWN|SET\s+OWNER)\b").unwrap()
});

impl Rule for SchemaOwnershipChangeRule {
    fn id(&self) -> &'static str { "SEC-AUTHZ-002" }
    fn name(&self) -> &'static str { "Schema Ownership Change" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthorization) }
    fn impact(&self) -> &'static str { "Schema owners have implicit full control over all objects. Ownership transfer can bypass explicit DENY permissions." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_AUTHZ_002.find(&query.raw).map(|m| {
            vec![self.build_issue(query, &format!("Schema ownership change detected: {}", m.as_str()), m.as_str())]
        }).unwrap_or_default()
    }
}

struct HorizontalAuthorizationBypassRule;
static SENSITIVE_TABLES: &[&str] = &[
    "orders", "transactions", "accounts", "profiles", "messages",
    "documents", "files", "payments", "invoices", "subscriptions",
    "user_data", "customer_data", "private_data",
];
static SCOPING_COLUMNS: &[&str] = &[
    "user_id", "tenant_id", "account_id", "owner_id", "customer_id",
    "org_id", "organization_id", "created_by", "belongs_to",
];

impl Rule for HorizontalAuthorizationBypassRule {
    fn id(&self) -> &'static str { "SEC-AUTHZ-003" }
    fn name(&self) -> &'static str { "Horizontal Authorization Bypass" }
    fn severity(&self) -> Severity { Severity::High }
    fn dimension(&self) -> Dimension { Dimension::Security }
    fn category(&self) -> Option<Category> { Some(Category::SecAuthorization) }
    fn impact(&self) -> &'static str { "Missing tenant isolation allows users to access other users data." }

    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() { return Vec::new(); }
        let upper = query.raw_upper();
        if upper.contains("COUNT(") || upper.contains("SUM(") || upper.contains("AVG(") { return Vec::new(); }
        let raw_lower = query.raw_lower().to_string();
        let hits_sensitive = SENSITIVE_TABLES.iter().any(|&t| raw_lower.contains(t));
        if !hits_sensitive { return Vec::new(); }
        let has_scoping = SCOPING_COLUMNS.iter().any(|&c| raw_lower.contains(c));
        if has_scoping { return Vec::new(); }
        vec![self.build_issue(
            query,
            "Query on sensitive table without user/tenant scoping column in WHERE clause",
            &query.raw[..query.raw.len().min(100)],
        )]
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(PrivilegeEscalationRoleGrantRule),
        Box::new(SchemaOwnershipChangeRule),
        Box::new(HorizontalAuthorizationBypassRule),
    ]
}
