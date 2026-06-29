use once_cell::sync::Lazy;
use regex::Regex;

pub const MIGRATION: &str = "migration";
pub const APPLICATION: &str = "application";
pub const TEST: &str = "test";
pub const SEED: &str = "seed";
pub const DDL_SCHEMA: &str = "ddl_schema";
pub const DBT_MODEL: &str = "dbt_model";
pub const EXAMPLE: &str = "example";
pub const FRAMEWORK_INTERNAL: &str = "framework_internal";
pub const ADHOC: &str = "adhoc";

static PATH_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)(?:^|/)alembic/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)migrations?/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)[_-]migrations?/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)migrator/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)snapshot/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)db/migrate/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)flyway/").unwrap(), MIGRATION),
        (Regex::new(r"(?i)(?:^|/)liquibase/").unwrap(), MIGRATION),
        (
            Regex::new(r"(?i)(?:^|/)prisma/migrations/").unwrap(),
            MIGRATION,
        ),
        (Regex::new(r"(?i)(?:^|/)tests?/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)spec/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)__tests__/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)e2e/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)\.circleci/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)\.github/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)\.gitlab-ci/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)test[_-]resources?/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)testdata/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)python-sources/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)python-sources/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)scripts?/").unwrap(), EXAMPLE),
        (
            Regex::new(r"(?i)(?:^|/)models?/.*\.sql$").unwrap(),
            DBT_MODEL,
        ),
        (Regex::new(r"(?i)(?:^|/)seeds?/").unwrap(), SEED),
        (Regex::new(r"(?i)(?:^|/)fixtures?/").unwrap(), SEED),
        (Regex::new(r"(?i)(?:^|/)seeders?/").unwrap(), SEED),
        (Regex::new(r"(?i)indexer_seeders?/").unwrap(), SEED),
        (Regex::new(r"(?i)(?:^|/)seed\.sql$").unwrap(), SEED),
        (Regex::new(r"(?i)/data\.sql$").unwrap(), SEED),
        (Regex::new(r"(?i)(?:^|/)schema\.sql$").unwrap(), DDL_SCHEMA),
        (
            Regex::new(r"(?i)(?:^|/)structure\.sql$").unwrap(),
            DDL_SCHEMA,
        ),
        (Regex::new(r"(?i)(?:^|/)schema/").unwrap(), DDL_SCHEMA),
        (Regex::new(r"(?i)(?:^|/)ddl/").unwrap(), DDL_SCHEMA),
        (Regex::new(r"(?i)(?:^|/)examples?/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)docs?/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)bench/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)benchmarks?/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)demo/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)samples?/").unwrap(), EXAMPLE),
        (
            Regex::new(r"(?i)(?:^|/)dataset_templates?/").unwrap(),
            EXAMPLE,
        ),
        (Regex::new(r"(?i)(?:^|/)\.semgrep/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)bin/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)devenv/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)docker/").unwrap(), EXAMPLE),
        // CI test/fuzz queries (e.g. ClickHouse ci/jobs/queries/)
        (Regex::new(r"(?i)(?:^|/)ci/").unwrap(), TEST),
        (Regex::new(r"(?i)_fuzz").unwrap(), TEST),
        // Configuration/initialization scripts (e.g. vitess config/init_db.sql)
        (Regex::new(r"(?i)(?:^|/)config/").unwrap(), DDL_SCHEMA),
        // Integration/golden test directories
        (Regex::new(r"(?i)(?:^|/)integration-tests?/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)golden/").unwrap(), TEST),
        (Regex::new(r"(?i)(?:^|/)roachtest/").unwrap(), TEST),
        // Development setup directories
        (Regex::new(r"(?i)(?:^|/)dev/").unwrap(), EXAMPLE),
        // Database system internal SQL (e.g. ClickHouse information_schema views)
        (
            Regex::new(r"(?i)(?:^|/)information_schema/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // PostgreSQL extension SQL (e.g. citus, timescaledb install/upgrade scripts)
        // Matches both versioned (name--version.sql) and non-versioned (name.sql)
        // extension SQL under a sql/ directory in database engine source trees.
        (
            Regex::new(r"(?i)(?:^|/)sql/[^/]+--[^/]+\.sql$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)columnar/sql/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // Extension SQL directories (e.g. timescaledb sql/updates/, sql/pre_install/)
        (
            Regex::new(r"(?i)(?:^|/)sql/updates/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)sql/pre_install/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // Top-level sql/ directory in database extensions (e.g. timescaledb/sql/*.sql)
        // These contain extension installation/upgrade PL/pgSQL, not application queries.
        (Regex::new(r"(?i)/sql/[^/]+\.sql$").unwrap(), DDL_SCHEMA),
        (
            Regex::new(r"(?i)/infer_schema").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // Database engine backend internals (e.g. citus src/backend/)
        // Contains extension/engine SQL, not application queries.
        (
            Regex::new(r"(?i)(?:^|/)src/backend/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // Documentation site content (e.g. mybatis-3 src/site/*/xdoc/)
        // SQL in these files is illustrative, not production code.
        (Regex::new(r"(?i)(?:^|/)src/site/").unwrap(), EXAMPLE),
        // Driver adapter infrastructure (e.g. prisma driver-adapters-manager)
        // Contains intentional teardown/reset SQL, not application queries.
        (
            Regex::new(r"(?i)(?:^|/)driver-adapters?/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)driver-adapters?-manager/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)src-rsr/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        // Security tool payload directories (e.g. sqlmap data/procs/, extra/vulnserver/)
        // SQL here is intentionally dangerous by design.
        (Regex::new(r"(?i)(?:^|/)data/procs/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)vulnserver/").unwrap(), EXAMPLE),
        (Regex::new(r"(?i)(?:^|/)src/").unwrap(), APPLICATION),
        // ORM and framework internal SQL adapter code
        // These files contain intentionally generic SQL templates
        (
            Regex::new(r"(?i)(?:^|/)connection_adapters?/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)db/backends?/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)db/models?/sql/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)lib/arel/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)(?:^|/)activerecord/lib/").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)/models/[^/]+/sql\.py$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)/[^/]+/sql\.py$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)/backend/sql\.py$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)/clickhouse/[^/]+\.py$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (
            Regex::new(r"(?i)/sql/[^/]+_sql\.py$").unwrap(),
            FRAMEWORK_INTERNAL,
        ),
        (Regex::new(r"(?i)_sql\.py$").unwrap(), FRAMEWORK_INTERNAL),
        (Regex::new(r"(?i)/dags/").unwrap(), FRAMEWORK_INTERNAL),
        (Regex::new(r"(?i)/management/").unwrap(), FRAMEWORK_INTERNAL),
        (Regex::new(r"(?i)/store/").unwrap(), FRAMEWORK_INTERNAL),
    ]
});

static CONTENT_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"(?im)revision\s*[:=].*\ndown_revision").unwrap(),
            MIGRATION,
        ),
        (
            Regex::new(r"(?m)class\s+\w*Migration\w*\s*\(").unwrap(),
            MIGRATION,
        ),
        (Regex::new(r"(?m)def\s+(up|down)\s*\(").unwrap(), MIGRATION),
        (
            Regex::new(r"(?i)--\s*(?:flyway|liquibase|prisma)").unwrap(),
            MIGRATION,
        ),
        (Regex::new(r"\{\{\s*ref\s*\(").unwrap(), DBT_MODEL),
        (
            Regex::new(r"\{%\s*(config|materialization)").unwrap(),
            DBT_MODEL,
        ),
    ]
});

/// Allowed rule prefixes for non-production contexts.
/// Production contexts (APPLICATION, ADHOC, DBT_MODEL) get full analysis.
fn allowed_prefixes(context: &str) -> Option<&'static [&'static str]> {
    match context {
        MIGRATION | TEST | SEED | EXAMPLE | FRAMEWORK_INTERNAL => Some(&["SEC-", "REL-"]),
        DDL_SCHEMA => Some(&["SEC-", "REL-", "COMP-"]),
        _ => None, // no filtering
    }
}

/// Rules denied even if prefix is allowed.
fn denied_rules(context: &str) -> &'static [&'static str] {
    match context {
        MIGRATION => &["SEC-INJ-005", "REL-DATA-004", "MIG-BRK-001"],
        TEST => &["REL-FK-002", "REL-DEAD-002", "SEC-AUTHZ-003"],
        SEED => &["SEC-INJ-005"],
        FRAMEWORK_INTERNAL => &["REL-DATA-004", "SEC-LOG-002", "SEC-INJ-008", "SEC-INJ-011"],
        APPLICATION | ADHOC => &["QUAL-DBT-001", "QUAL-DBT-002"],
        DBT_MODEL => &["PERF-SCAN-003"],
        _ => &[],
    }
}

/// Classify the source context of a SQL file.
pub fn classify_source(file_path: Option<&str>, content: &str) -> &'static str {
    if let Some(path) = file_path {
        let normalized = path.replace('\\', "/");
        // Check for test file naming FIRST, before any path pattern.
        // These are always test files regardless of directory path.
        let filename = normalized.rsplit('/').next().unwrap_or(&normalized);
        if filename.contains(".spec.")
            || filename.contains(".test.")
            || filename.contains("_spec.")
            || filename.contains("_test.")
            || filename.starts_with("test_")
            || filename.contains("testinfra")
            || filename.contains("test_infra")
            || filename == "conftest.py"
            || filename == "tests.py"
        {
            return TEST;
        }
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

    // .sql files provided as input default to application context
    if let Some(path) = file_path {
        if path.ends_with(".sql") {
            return APPLICATION;
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
                issues
                    .into_iter()
                    .filter(|i| !denied.contains(&i.rule_id.as_str()))
                    .collect()
            }
        }
        Some(allowed) => issues
            .into_iter()
            .filter(|i| {
                if denied.contains(&i.rule_id.as_str()) {
                    return false;
                }
                allowed.iter().any(|prefix| i.rule_id.starts_with(prefix))
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_migration_paths() {
        assert_eq!(
            classify_source(Some("alembic/versions/001.py"), ""),
            MIGRATION
        );
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
    fn classify_framework_internal_and_example_paths() {
        assert_eq!(
            classify_source(Some("server/src-rsr/pg_table_metadata.sql"), ""),
            FRAMEWORK_INTERNAL
        );
        assert_eq!(
            classify_source(
                Some("server/lib/pg-client/bench/queries/allArtists.sql"),
                ""
            ),
            EXAMPLE
        );
        assert_eq!(
            classify_source(
                Some("dc-agents/sqlite/dataset_templates/TestingEdgeCases.sql"),
                ""
            ),
            EXAMPLE
        );
    }

    #[test]
    fn classify_adhoc() {
        assert_eq!(classify_source(None, "SELECT 1"), ADHOC);
        assert_eq!(
            classify_source(Some("queries.sql"), "SELECT 1"),
            APPLICATION
        );
    }

    #[test]
    fn classify_dbt_by_content() {
        assert_eq!(
            classify_source(None, "SELECT {{ ref('users') }}"),
            DBT_MODEL
        );
    }

    #[test]
    fn filter_migration_context() {
        use crate::models::{Dimension, Issue, Location, Severity};
        let issues = vec![
            Issue::new(
                "SEC-INJ-001",
                "sec",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "PERF-SCAN-001",
                "perf",
                Severity::Medium,
                Dimension::Performance,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "REL-DATA-001",
                "rel",
                Severity::Critical,
                Dimension::Reliability,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "SEC-INJ-005",
                "denied",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
        ];
        let filtered = filter_issues_by_context(issues, MIGRATION);
        assert_eq!(filtered.len(), 2); // SEC-INJ-001 + REL-DATA-001 (SEC-INJ-005 denied, PERF filtered)
        assert!(filtered.iter().any(|i| i.rule_id == "SEC-INJ-001"));
        assert!(filtered.iter().any(|i| i.rule_id == "REL-DATA-001"));
    }

    #[test]
    fn filter_framework_internal_context_denies_known_internal_noise() {
        use crate::models::{Dimension, Issue, Location, Severity};
        let issues = vec![
            Issue::new(
                "SEC-INJ-001",
                "keep",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "SEC-INJ-008",
                "deny",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "SEC-INJ-011",
                "deny",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "REL-DATA-004",
                "deny",
                Severity::High,
                Dimension::Reliability,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "SEC-LOG-002",
                "deny",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "PERF-SCAN-001",
                "filtered_by_prefix",
                Severity::Medium,
                Dimension::Performance,
                Location::new(1, 1),
                "x",
            ),
        ];
        let filtered = filter_issues_by_context(issues, FRAMEWORK_INTERNAL);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "SEC-INJ-001");
    }
}
