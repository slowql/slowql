use regex::Regex;
use once_cell::sync::Lazy;

pub const MIGRATION: &str = "migration";
pub const APPLICATION: &str = "application";
pub const TEST: &str = "test";
pub const SEED: &str = "seed";
pub const DDL_SCHEMA: &str = "ddl_schema";
pub const DBT_MODEL: &str = "dbt_model";
pub const ADHOC: &str = "adhoc";

static PATH_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?i)(?:^|/)alembic/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)migrations?/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)db/migrate/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)flyway/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)liquibase/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)prisma/migrations/").unwrap(), MIGRATION),
    (Regex::new(r"(?i)(?:^|/)tests?/").unwrap(), TEST),
    (Regex::new(r"(?i)(?:^|/)spec/").unwrap(), TEST),
    (Regex::new(r"(?i)(?:^|/)__tests__/").unwrap(), TEST),
    (Regex::new(r"(?i)(?:^|/)models?/.*\.sql$").unwrap(), DBT_MODEL),
    (Regex::new(r"(?i)(?:^|/)seeds?/").unwrap(), SEED),
    (Regex::new(r"(?i)(?:^|/)fixtures?/").unwrap(), SEED),
    (Regex::new(r"(?i)(?:^|/)schema\.sql$").unwrap(), DDL_SCHEMA),
    (Regex::new(r"(?i)(?:^|/)schema/").unwrap(), DDL_SCHEMA),
    (Regex::new(r"(?i)(?:^|/)ddl/").unwrap(), DDL_SCHEMA),
    (Regex::new(r"(?i)(?:^|/)src/").unwrap(), APPLICATION),
]);

static CONTENT_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?im)revision\s*[:=].*\ndown_revision").unwrap(), MIGRATION),
    (Regex::new(r"(?m)class\s+\w*Migration\w*\s*\(").unwrap(), MIGRATION),
    (Regex::new(r"(?m)def\s+(up|down)\s*\(").unwrap(), MIGRATION),
    (Regex::new(r"(?i)--\s*(?:flyway|liquibase|prisma)").unwrap(), MIGRATION),
    (Regex::new(r"\{\{\s*ref\s*\(").unwrap(), DBT_MODEL),
    (Regex::new(r"\{%\s*(config|materialization)").unwrap(), DBT_MODEL),
]);

/// Allowed rule prefixes for non-production contexts.
/// Production contexts (APPLICATION, ADHOC, DBT_MODEL) get full analysis.
fn allowed_prefixes(context: &str) -> Option<&'static [&'static str]> {
    match context {
        MIGRATION | TEST | SEED => Some(&["SEC-", "REL-"]),
        DDL_SCHEMA => Some(&["SEC-", "REL-", "COMP-"]),
        _ => None, // no filtering
    }
}

/// Rules denied even if prefix is allowed.
fn denied_rules(context: &str) -> &'static [&'static str] {
    match context {
        MIGRATION => &["SEC-INJ-005"],
        TEST => &["REL-FK-002", "REL-DEAD-002", "SEC-AUTHZ-003"],
        SEED => &["SEC-INJ-005"],
        APPLICATION | ADHOC => &["QUAL-DBT-001", "QUAL-DBT-002"],
        DBT_MODEL => &["PERF-SCAN-003"],
        _ => &[],
    }
}

/// Classify the source context of a SQL file.
pub fn classify_source(file_path: Option<&str>, content: &str) -> &'static str {
    if let Some(path) = file_path {
        let normalized = path.replace('\\', "/");
        for (pattern, ctx) in PATH_PATTERNS.iter() {
            if pattern.is_match(&normalized) {
                return ctx;
            }
        }
        let ext = normalized.rsplit('.').next().unwrap_or("");
        if matches!(ext, "py" | "ts" | "js" | "java" | "go" | "rb" | "kt" | "cs") {
            return APPLICATION;
        }
        if ext == "xml" {
            return APPLICATION;
        }
    }

    for (pattern, ctx) in CONTENT_PATTERNS.iter() {
        if pattern.is_match(content) {
            return ctx;
        }
    }

    ADHOC
}

/// Filter issues by source context.
pub fn filter_issues_by_context(
    issues: Vec<crate::models::Issue>,
    source_context: &str,
) -> Vec<crate::models::Issue> {
    let denied = denied_rules(source_context);

    match allowed_prefixes(source_context) {
        None => {
            // Production context: only deny list
            if denied.is_empty() {
                issues
            } else {
                issues.into_iter().filter(|i| !denied.contains(&i.rule_id.as_str())).collect()
            }
        }
        Some(allowed) => {
            issues.into_iter().filter(|i| {
                if denied.contains(&i.rule_id.as_str()) {
                    return false;
                }
                allowed.iter().any(|prefix| i.rule_id.starts_with(prefix))
            }).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_migration_paths() {
        assert_eq!(classify_source(Some("alembic/versions/001.py"), ""), MIGRATION);
        assert_eq!(classify_source(Some("db/migrate/001.sql"), ""), MIGRATION);
        assert_eq!(classify_source(Some("migrations/001.sql"), ""), MIGRATION);
    }

    #[test]
    fn classify_test_paths() {
        assert_eq!(classify_source(Some("tests/test_queries.sql"), ""), TEST);
        assert_eq!(classify_source(Some("spec/models.sql"), ""), TEST);
    }

    #[test]
    fn classify_seed_paths() {
        assert_eq!(classify_source(Some("seeds/data.sql"), ""), SEED);
        assert_eq!(classify_source(Some("fixtures/users.sql"), ""), SEED);
    }

    #[test]
    fn classify_adhoc() {
        assert_eq!(classify_source(None, "SELECT 1"), ADHOC);
        assert_eq!(classify_source(Some("queries.sql"), "SELECT 1"), ADHOC);
    }

    #[test]
    fn classify_dbt_by_content() {
        assert_eq!(classify_source(None, "SELECT {{ ref('users') }}"), DBT_MODEL);
    }

    #[test]
    fn filter_migration_context() {
        use crate::models::{Dimension, Issue, Location, Severity};
        let issues = vec![
            Issue::new("SEC-INJ-001", "sec", Severity::High, Dimension::Security, Location::new(1,1), "x"),
            Issue::new("PERF-SCAN-001", "perf", Severity::Medium, Dimension::Performance, Location::new(1,1), "x"),
            Issue::new("REL-DATA-001", "rel", Severity::Critical, Dimension::Reliability, Location::new(1,1), "x"),
            Issue::new("SEC-INJ-005", "denied", Severity::High, Dimension::Security, Location::new(1,1), "x"),
        ];
        let filtered = filter_issues_by_context(issues, MIGRATION);
        assert_eq!(filtered.len(), 2); // SEC-INJ-001 + REL-DATA-001 (SEC-INJ-005 denied, PERF filtered)
        assert!(filtered.iter().any(|i| i.rule_id == "SEC-INJ-001"));
        assert!(filtered.iter().any(|i| i.rule_id == "REL-DATA-001"));
    }
}
