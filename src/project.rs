//! Project-level analysis: cross-file breaking changes, dead SQL detection,
//! and duplicate query detection. Operates on the combined set of all parsed
//! queries after individual file analysis is complete.

use crate::models::issue::{Category, Location, RuleConfidence};
use crate::models::result::AnalysisResult;
use crate::models::{Dimension, Issue, Severity};
use std::collections::{HashMap, HashSet};

/// Run all project-level checks on the combined analysis result.
/// Returns additional issues to append.
pub fn analyze_project(result: &AnalysisResult) -> Vec<Issue> {
    // Skip all project-level cross-file analysis on very large corpora.
    // These checks require holding all queries in memory and building indexes.
    // Above 50 000 queries the cost exceeds the value for non-application corpora.
    // Time: O(1) guard. Space: O(1).
    const MAX_QUERIES_FOR_PROJECT_ANALYSIS: usize = 20_000;
    if result.queries.len() > MAX_QUERIES_FOR_PROJECT_ANALYSIS {
        return Vec::new();
    }
    let mut issues = Vec::new();
    issues.extend(detect_cross_file_breaks(result));
    issues.extend(detect_unused_objects(result));
    issues.extend(detect_duplicate_queries(result));
    issues
}

/// SCH-BRK-001: Detect when a DROP COLUMN or DROP TABLE in one file
/// breaks a reference in another file.
///
/// Time:  O(Q + T*avg_refs + C*avg_refs) where Q=queries, T=dropped tables, C=dropped columns.
///        HashSet/HashMap lookups replace the previous O(Q*(T+C)) nested scan.
/// Space: O(T + C) for the two index structures.
///
/// Skips analysis entirely when query count exceeds 50 000, because cross-file
/// analysis is only meaningful for focused application codebases.
fn detect_cross_file_breaks(result: &AnalysisResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Phase 1: index all DROP TABLE and DROP COLUMN statements.
    // Key: lowercase table name -> vec of (original_name, source_file).
    let mut dropped_table_index: HashMap<String, Vec<(String, String)>> = HashMap::new();
    // Key: (lowercase_table, lowercase_col) -> vec of (table, col, source_file).
    let mut dropped_col_index: HashMap<(String, String), Vec<(String, String, String)>> =
        HashMap::new();

    for query in &result.queries {
        let upper = query.raw_upper();
        let file = query.location.file.as_deref().unwrap_or("").to_string();

        if upper.contains("DROP TABLE") {
            if let Some(name) = extract_drop_table_name(upper) {
                dropped_table_index
                    .entry(name.to_lowercase())
                    .or_default()
                    .push((name, file));
            }
        } else if upper.contains("DROP COLUMN") {
            if let Some((tbl, col)) = extract_drop_column(upper) {
                dropped_col_index
                    .entry((tbl.to_lowercase(), col.to_lowercase()))
                    .or_default()
                    .push((tbl, col, file));
            }
        }
    }

    if dropped_table_index.is_empty() && dropped_col_index.is_empty() {
        return Vec::new();
    }

    let dialect_prefixes: &[&str] = &[
        "h2-",
        "mysql-",
        "postgres-",
        "postgresql-",
        "mariadb-",
        "sqlite-",
        "oracle-",
        "mssql-",
        "tsql-",
        "redshift-",
        "snowflake-",
        "bigquery-",
        "clickhouse-",
        "duckdb-",
        "presto-",
        "trino-",
        "spark-",
        "databricks-",
    ];

    // Phase 2: for each query, check only tables/columns it actually uses.
    // Inner lookup is O(1) via HashMap; no nested scan over all drops.
    for query in &result.queries {
        let file = query.location.file.as_deref().unwrap_or("");
        let file_dir = file.rsplit('/').nth(1).unwrap_or("");
        let file_name = file.rsplit('/').next().unwrap_or("");
        let file_lower = file.to_lowercase();
        let file_in_migration =
            file_lower.contains("/migrations/") || file_lower.contains("/initialization/");
        let file_is_dialect = dialect_prefixes.iter().any(|p| file_name.starts_with(p));

        for table in &query.tables {
            let lower_table = table.to_lowercase();

            // Check dropped tables.
            if let Some(drops) = dropped_table_index.get(&lower_table) {
                for (orig_name, drop_file) in drops {
                    if file == drop_file {
                        continue;
                    }
                    let drop_dir = drop_file.rsplit('/').nth(1).unwrap_or("");
                    if !file_dir.is_empty() && file_dir == drop_dir {
                        continue;
                    }
                    let drop_name = drop_file.rsplit('/').next().unwrap_or("");
                    if file_is_dialect || dialect_prefixes.iter().any(|p| drop_name.starts_with(p))
                    {
                        continue;
                    }
                    let drop_lower = drop_file.to_lowercase();
                    if file_in_migration
                        && (drop_lower.contains("/migrations/")
                            || drop_lower.contains("/initialization/"))
                    {
                        continue;
                    }
                    let msg = format!(
                        "Cross-file breaking change: table '{}' is dropped in {} but referenced here.",
                        orig_name,
                        short_path(drop_file)
                    );
                    let mut issue = Issue::new(
                        "SCH-BRK-001",
                        msg,
                        Severity::High,
                        Dimension::Schema,
                        query.location.clone(),
                        query.snippet(100),
                    );
                    issue.category = Some(Category::RelDataIntegrity);
                    issue.confidence = RuleConfidence::Contextual;
                    issue.source_context = query.source_context.clone();
                    issues.push(issue);
                }
            }

            // Check dropped columns for this table.
            for col in &query.columns {
                let key = (lower_table.clone(), col.to_lowercase());
                if let Some(drops) = dropped_col_index.get(&key) {
                    for (orig_tbl, orig_col, drop_file) in drops {
                        if file == drop_file {
                            continue;
                        }
                        let msg = format!(
                            "Cross-file breaking change: column '{}.{}' is dropped in {} but referenced here.",
                            orig_tbl, orig_col, short_path(drop_file)
                        );
                        let mut issue = Issue::new(
                            "SCH-BRK-001",
                            msg,
                            Severity::High,
                            Dimension::Schema,
                            query.location.clone(),
                            query.snippet(100),
                        );
                        issue.category = Some(Category::RelDataIntegrity);
                        issue.confidence = RuleConfidence::Contextual;
                        issue.source_context = query.source_context.clone();
                        issues.push(issue);
                    }
                }
            }
        }
    }

    issues
}

fn detect_unused_objects(result: &AnalysisResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Collect defined objects: (object_type, name, location, file)
    let mut defined: Vec<(String, String, Location, String)> = Vec::new();
    // Collect all referenced names across the project
    let mut referenced: HashSet<String> = HashSet::new();

    for query in &result.queries {
        let upper = query.raw_upper();
        let file = query.location.file.as_deref().unwrap_or("").to_string();

        // Detect definitions
        for keyword in &[
            "CREATE VIEW",
            "CREATE OR REPLACE VIEW",
            "CREATE FUNCTION",
            "CREATE OR REPLACE FUNCTION",
            "CREATE PROCEDURE",
            "CREATE OR REPLACE PROCEDURE",
        ] {
            if upper.contains(keyword) {
                if let Some(name) = extract_object_name(upper, keyword) {
                    defined.push((
                        keyword.to_string(),
                        name,
                        query.location.clone(),
                        file.clone(),
                    ));
                }
            }
        }

        // Collect all table/view references
        for table in &query.tables {
            referenced.insert(table.to_lowercase());
        }

        // Check raw SQL for function/procedure calls.
        // Use a single pass with char_indices to find "word(" patterns.
        // Time: O(raw_length) per query. Space: O(1) auxiliary.
        // Previous implementation was O(words * raw_length) per query.
        {
            let raw_lower = query.raw_lower();
            let bytes = raw_lower.as_bytes();
            let len = bytes.len();
            let mut i = 0;
            while i < len {
                // Find '('
                if bytes[i] == b'(' && i > 0 {
                    // Walk backwards to find the start of the identifier
                    let end = i;
                    let mut start = i;
                    while start > 0
                        && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
                    {
                        start -= 1;
                    }
                    if start < end {
                        let word = &raw_lower[start..end];
                        if !word.is_empty() {
                            referenced.insert(word.to_string());
                        }
                    }
                }
                i += 1;
            }
        }
    }

    for (obj_type, name, location, _file) in &defined {
        let lower_name = name.to_lowercase();
        // Strip schema prefix for matching
        let base_name = lower_name.rsplit('.').next().unwrap_or(&lower_name);
        if !referenced.contains(base_name) {
            let msg =
                format!(
                "Unused database object: {} '{}' is defined but never referenced in the project.",
                obj_type.replace("CREATE OR REPLACE ", "").replace("CREATE ", ""),
                name
            );
            let mut issue = Issue::new(
                "QUAL-DEAD-001",
                msg,
                Severity::Medium,
                Dimension::Quality,
                location.clone(),
                name.clone(),
            );
            issue.category = Some(Category::QualTechDebt);
            issue.confidence = RuleConfidence::Advisory;
            // Infer source context from file path
            issue.source_context = infer_context_from_path(_file);
            issues.push(issue);
        }
    }

    issues
}

/// QUAL-DEAD-003: Detect queries with identical normalized SQL appearing
/// in multiple locations.
fn detect_duplicate_queries(result: &AnalysisResult) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut seen: HashMap<String, Vec<Location>> = HashMap::new();

    for query in &result.queries {
        if query.normalized.is_empty() {
            continue;
        }
        // Skip DDL and admin queries
        let qt = query.query_type.as_deref().unwrap_or("");
        if !matches!(qt, "SELECT" | "INSERT" | "UPDATE" | "DELETE") {
            continue;
        }
        // Skip non-production queries (test, example, seed)
        let file = query.location.file.as_deref().unwrap_or("");
        if file.contains("/test/")
            || file.contains("/tests/")
            || file.contains("/spec/")
            || file.contains("/examples/")
            || file.contains("/fixtures/")
            || file.contains("/__tests__/")
            || file.contains("/testdata/")
            || file.contains("/endtoend/")
            || file.ends_with("_test.go")
        {
            continue;
        }

        let key = query.normalized.to_uppercase();
        seen.entry(key).or_default().push(query.location.clone());
    }

    for (normalized, locations) in &seen {
        if locations.len() < 2 {
            continue;
        }
        // Only report at the second occurrence
        for loc in &locations[1..] {
            let first_file = locations[0].file.as_deref().unwrap_or("unknown");
            let msg = format!(
                "Duplicate query detected. Same query also appears at {}:{}.",
                short_path(first_file),
                locations[0].line
            );
            let mut issue = Issue::new(
                "QUAL-DEAD-003",
                msg,
                Severity::Low,
                Dimension::Quality,
                loc.clone(),
                &normalized[..normalized.len().min(80)],
            );
            issue.category = Some(Category::QualTechDebt);
            issue.confidence = RuleConfidence::Advisory;
            issue.source_context = infer_context_from_path(loc.file.as_deref().unwrap_or(""));
            issues.push(issue);
        }
    }

    issues
}

// Helper functions

fn extract_drop_table_name(upper: &str) -> Option<String> {
    let idx = upper.find("DROP TABLE")?;
    let after = &upper[idx + "DROP TABLE".len()..];
    let after = after.trim_start();
    let after = if let Some(stripped) = after.strip_prefix("IF EXISTS") {
        stripped.trim_start()
    } else {
        after
    };
    let name = after
        .split(|c: char| c.is_whitespace() || c == ';' || c == '(')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn extract_drop_column(upper: &str) -> Option<(String, String)> {
    let idx = upper.find("ALTER TABLE")?;
    let after = &upper[idx + "ALTER TABLE".len()..].trim_start();
    let table = after
        .split_whitespace()
        .next()?
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');

    let col_idx = upper.find("DROP COLUMN")?;
    let after_col = &upper[col_idx + "DROP COLUMN".len()..].trim_start();
    let col = after_col
        .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');

    if table.is_empty() || col.is_empty() {
        None
    } else {
        Some((table.to_string(), col.to_string()))
    }
}

fn is_valid_object_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    // Time: O(len(name))
    // Space: O(1)
    // Accept standard SQL identifiers and schema-qualified names.
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn extract_object_name(upper: &str, keyword: &str) -> Option<String> {
    let idx = upper.find(keyword)?;
    let after = &upper[idx + keyword.len()..].trim_start();
    let name = after
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';' || c == ',')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');

    if name.is_empty() || name == "AS" || !is_valid_object_name(name) {
        None
    } else {
        Some(name.to_string())
    }
}

fn infer_context_from_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.contains("/spec/")
        || lower.contains("/__tests__/")
        || lower.contains("/e2e/")
        || lower.contains(".spec.")
        || lower.contains(".test.")
        || lower.contains("/test_resources/")
        || lower.contains("/test-resources/")
    {
        "test".to_string()
    } else if lower.contains("/migration/")
        || lower.contains("/migrations/")
        || lower.contains("/db/migrate/")
    {
        "migration".to_string()
    } else if lower.contains("/example/")
        || lower.contains("/examples/")
        || lower.contains("/doc/")
        || lower.contains("/docs/")
        || lower.contains("/demo/")
        || lower.contains("/scripts/")
        || lower.contains("/script/")
    {
        "example".to_string()
    } else if lower.contains("/seed/")
        || lower.contains("/seeds/")
        || lower.contains("/fixtures/")
        || lower.ends_with("/seed.sql")
        || lower.ends_with("/data.sql")
    {
        "seed".to_string()
    } else if lower.contains("/connection_adapter")
        || lower.contains("/db/backends/")
        || lower.contains("/db/models/sql/")
        || lower.contains("/lib/arel/")
        || lower.contains("/activerecord/lib/")
    {
        "framework_internal".to_string()
    } else if lower.ends_with("/structure.sql")
        || lower.ends_with("/schema.sql")
        || lower.contains("/schema/")
        || lower.contains("/ddl/")
    {
        "ddl_schema".to_string()
    } else {
        "application".to_string()
    }
}

fn short_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::query::Query;

    fn make_query(sql: &str, file: &str) -> Query {
        let mut q = Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file(file),
            query_type: Some(
                sql.split_whitespace()
                    .next()
                    .unwrap_or("SELECT")
                    .to_uppercase(),
            ),
            ..Default::default()
        };
        // Populate tables from parser
        let parsed = crate::parser::parse(sql, "postgresql", Some(file));
        if let Some(first) = parsed.first() {
            q.tables = first.tables.clone();
            q.columns = first.columns.clone();
        }
        q
    }

    #[test]
    fn cross_file_drop_table_detected() {
        let mut result = AnalysisResult::new();
        result
            .queries
            .push(make_query("DROP TABLE users", "migrations/001.sql"));
        result.queries.push(make_query(
            "SELECT id, name FROM users WHERE id = 1",
            "src/app.sql",
        ));

        let issues = analyze_project(&result);
        assert!(
            issues.iter().any(|i| i.rule_id == "SCH-BRK-001"),
            "should detect cross-file break when DROP TABLE and SELECT reference same table"
        );
    }

    #[test]
    fn same_file_drop_not_cross_file() {
        let mut result = AnalysisResult::new();
        result
            .queries
            .push(make_query("DROP TABLE temp_data", "cleanup.sql"));
        result
            .queries
            .push(make_query("CREATE TABLE temp_data (id INT)", "cleanup.sql"));

        let issues = analyze_project(&result);
        assert!(
            !issues.iter().any(|i| i.rule_id == "SCH-BRK-001"),
            "same-file DROP should not be flagged as cross-file break"
        );
    }

    #[test]
    fn duplicate_query_detected() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("SELECT id FROM users WHERE active = true", "src/a.sql");
        q1.query_type = Some("SELECT".to_string());
        q1.normalized = "SELECT id FROM users WHERE active = true".to_string();
        let mut q2 = make_query("SELECT id FROM users WHERE active = true", "src/b.sql");
        q2.query_type = Some("SELECT".to_string());
        q2.normalized = "SELECT id FROM users WHERE active = true".to_string();
        result.queries.push(q1);
        result.queries.push(q2);

        let issues = analyze_project(&result);
        assert!(
            issues.iter().any(|i| i.rule_id == "QUAL-DEAD-003"),
            "should detect duplicate queries across files"
        );
    }

    #[test]
    fn no_false_duplicate_on_different_queries() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("SELECT id FROM users", "src/a.sql");
        q1.query_type = Some("SELECT".to_string());
        q1.normalized = "SELECT id FROM users".to_string();
        let mut q2 = make_query("SELECT name FROM users", "src/b.sql");
        q2.query_type = Some("SELECT".to_string());
        q2.normalized = "SELECT name FROM users".to_string();
        result.queries.push(q1);
        result.queries.push(q2);

        let issues = analyze_project(&result);
        assert!(
            !issues.iter().any(|i| i.rule_id == "QUAL-DEAD-003"),
            "different queries should not be flagged as duplicates"
        );
    }

    #[test]
    fn cross_file_drop_column_detected() {
        let mut result = AnalysisResult::new();
        result.queries.push(make_query(
            "ALTER TABLE users DROP COLUMN email",
            "migrations/002.sql",
        ));
        let mut q2 = make_query("SELECT id, email FROM users WHERE id = 1", "src/app.sql");
        q2.columns = vec!["id".to_string(), "email".to_string()];
        result.queries.push(q2);

        let issues = analyze_project(&result);
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "SCH-BRK-001" && i.message.contains("column")),
            "should detect cross-file column drop"
        );
    }

    #[test]
    fn unused_view_detected() {
        let mut result = AnalysisResult::new();
        // Build query manually to avoid parser adding view name to tables
        result.queries.push(Query {
            raw: "CREATE VIEW unused_view AS SELECT 1 FROM t".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/views.sql"),
            query_type: Some("CREATE".to_string()),
            tables: vec!["t".to_string()],
            columns: vec![],
            ..Default::default()
        });
        result.queries.push(Query {
            raw: "SELECT id FROM other_table WHERE id = 1".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/app.sql"),
            query_type: Some("SELECT".to_string()),
            tables: vec!["other_table".to_string()],
            columns: vec![],
            ..Default::default()
        });

        let issues = detect_unused_objects(&result);
        assert!(
            issues.iter().any(|i| i.rule_id == "QUAL-DEAD-001"),
            "should detect unused view"
        );
    }

    #[test]
    fn used_view_not_flagged() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("CREATE VIEW my_view AS SELECT 1", "src/views.sql");
        q1.query_type = Some("CREATE".to_string());
        result.queries.push(q1);

        let mut q2 = make_query("SELECT * FROM my_view", "src/app.sql");
        q2.tables = vec!["my_view".to_string()];
        result.queries.push(q2);

        let issues = analyze_project(&result);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "QUAL-DEAD-001" && i.message.contains("my_view")),
            "used view should not be flagged"
        );
    }

    #[test]
    fn same_directory_drop_not_cross_file() {
        let mut result = AnalysisResult::new();
        result
            .queries
            .push(make_query("DROP TABLE users", "db/v1/h2-schema.sql"));
        result.queries.push(make_query(
            "SELECT id FROM users WHERE id = 1",
            "db/v1/mysql-schema.sql",
        ));
        let issues = detect_cross_file_breaks(&result);
        assert!(
            issues.is_empty(),
            "same-directory dialect variants should not flag"
        );
    }

    #[test]
    fn migration_dir_drop_not_cross_file() {
        let mut result = AnalysisResult::new();
        result
            .queries
            .push(make_query("DROP TABLE old_data", "db/migrations/001.sql"));
        result.queries.push(make_query(
            "SELECT * FROM old_data",
            "db/migrations/002.sql",
        ));
        let issues = detect_cross_file_breaks(&result);
        assert!(
            issues.is_empty(),
            "both files in migrations/ should not flag"
        );
    }

    #[test]
    fn dialect_prefix_drop_not_cross_file() {
        let mut result = AnalysisResult::new();
        result
            .queries
            .push(make_query("DROP TABLE users", "db/h2-init.sql"));
        result.queries.push(make_query(
            "SELECT id FROM users WHERE id = 1",
            "src/app.sql",
        ));
        let issues = detect_cross_file_breaks(&result);
        assert!(issues.is_empty(), "dialect-prefixed file should not flag");
    }

    #[test]
    fn test_context_duplicate_not_flagged() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("SELECT id FROM users", "project/tests/test_a.sql");
        q1.query_type = Some("SELECT".to_string());
        q1.normalized = "SELECT id FROM users".to_string();
        let mut q2 = make_query("SELECT id FROM users", "project/tests/test_b.sql");
        q2.query_type = Some("SELECT".to_string());
        q2.normalized = "SELECT id FROM users".to_string();
        result.queries.push(q1);
        result.queries.push(q2);

        let issues = detect_duplicate_queries(&result);
        assert!(issues.is_empty(), "test files should not flag duplicates");
    }

    #[test]
    fn extract_helpers() {
        assert_eq!(
            extract_drop_table_name("DROP TABLE IF EXISTS users"),
            Some("users".to_string())
        );
        assert_eq!(
            extract_drop_table_name("DROP TABLE users"),
            Some("users".to_string())
        );
        assert_eq!(extract_drop_table_name("SELECT 1"), None);
        assert_eq!(
            extract_drop_column("ALTER TABLE users DROP COLUMN email"),
            Some(("users".to_string(), "email".to_string()))
        );
        assert_eq!(extract_drop_column("SELECT 1"), None);
        assert_eq!(
            extract_object_name("CREATE VIEW my_view AS SELECT 1", "CREATE VIEW"),
            Some("my_view".to_string())
        );
        assert_eq!(
            extract_object_name("CREATE VIEW AS SELECT 1", "CREATE VIEW"),
            None
        );
        assert_eq!(
            extract_object_name(
                "GRANT SELECT, CREATE VIEW, SHOW VIEW ON *.* TO 'x'@'localhost'",
                "CREATE VIEW"
            ),
            None
        );
        assert_eq!(extract_object_name("SELECT 1", "CREATE VIEW"), None);
    }

    #[test]
    fn infer_context_paths() {
        assert_eq!(infer_context_from_path("project/tests/test_a.sql"), "test");
        assert_eq!(infer_context_from_path("src/app.sql"), "application");
        assert_eq!(
            infer_context_from_path("db/migrations/001.sql"),
            "migration"
        );
        assert_eq!(
            infer_context_from_path("project/examples/demo.sql"),
            "example"
        );
        assert_eq!(infer_context_from_path("project/seeds/data.sql"), "seed");
        assert_eq!(
            infer_context_from_path("db/schema/tables.sql"),
            "ddl_schema"
        );
        assert_eq!(
            infer_context_from_path("lib/db/backends/pg.py"),
            "framework_internal"
        );
    }

    #[test]
    fn unused_function_detected() {
        let mut result = AnalysisResult::new();
        result.queries.push(Query {
            raw: "CREATE FUNCTION unused_func RETURNS void AS $$ BEGIN END $$".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/funcs.sql"),
            query_type: Some("CREATE".to_string()),
            tables: vec![],
            columns: vec![],
            ..Default::default()
        });
        result.queries.push(Query {
            raw: "SELECT id FROM users WHERE id = 1".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/app.sql"),
            query_type: Some("SELECT".to_string()),
            tables: vec!["users".to_string()],
            columns: vec![],
            ..Default::default()
        });

        let issues = detect_unused_objects(&result);
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "QUAL-DEAD-001" && i.message.contains("UNUSED_FUNC")),
            "should detect unused function"
        );
    }

    #[test]
    fn unused_procedure_detected() {
        let mut result = AnalysisResult::new();
        result.queries.push(Query {
            raw: "CREATE OR REPLACE PROCEDURE unused_proc AS $$ BEGIN END $$".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/procs.sql"),
            query_type: Some("CREATE".to_string()),
            tables: vec![],
            columns: vec![],
            ..Default::default()
        });
        result.queries.push(Query {
            raw: "SELECT id FROM users WHERE id = 1".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/app.sql"),
            query_type: Some("SELECT".to_string()),
            tables: vec!["users".to_string()],
            columns: vec![],
            ..Default::default()
        });

        let issues = detect_unused_objects(&result);
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "QUAL-DEAD-001" && i.message.contains("UNUSED_PROC")),
            "should detect unused procedure"
        );
    }

    #[test]
    fn ddl_queries_not_duplicate() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("CREATE TABLE t (id INT)", "src/a.sql");
        q1.query_type = Some("CREATE".to_string());
        q1.normalized = "CREATE TABLE t (id INT)".to_string();
        let mut q2 = make_query("CREATE TABLE t (id INT)", "src/b.sql");
        q2.query_type = Some("CREATE".to_string());
        q2.normalized = "CREATE TABLE t (id INT)".to_string();
        result.queries.push(q1);
        result.queries.push(q2);

        let issues = detect_duplicate_queries(&result);
        assert!(issues.is_empty(), "DDL should not flag as duplicate");
    }

    #[test]
    fn empty_normalized_not_duplicate() {
        let mut result = AnalysisResult::new();
        let mut q1 = make_query("SELECT 1", "src/a.sql");
        q1.query_type = Some("SELECT".to_string());
        q1.normalized = String::new();
        result.queries.push(q1);

        let issues = detect_duplicate_queries(&result);
        assert!(issues.is_empty());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::models::query::Query;

    #[test]
    fn extract_drop_table_name_returns_none_when_name_missing() {
        assert_eq!(extract_drop_table_name("DROP TABLE IF EXISTS"), None);
    }

    #[test]
    fn extract_drop_column_returns_none_when_column_missing() {
        assert_eq!(extract_drop_column("ALTER TABLE users DROP COLUMN"), None);
    }

    #[test]
    fn function_reference_prevents_unused_function_issue() {
        let mut result = AnalysisResult::new();
        result.queries.push(Query {
            raw: "CREATE FUNCTION my_func RETURNS INT AS $$ BEGIN RETURN 1; END $$".to_string(),
            normalized: String::new(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/funcs.sql"),
            query_type: Some("CREATE".to_string()),
            tables: vec![],
            columns: vec![],
            ..Default::default()
        });
        result.queries.push(Query {
            raw: "SELECT my_func(id) FROM users".to_string(),
            normalized: "SELECT my_func(id) FROM users".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("src/app.sql"),
            query_type: Some("SELECT".to_string()),
            tables: vec!["users".to_string()],
            columns: vec!["id".to_string()],
            ..Default::default()
        });

        let issues = detect_unused_objects(&result);
        assert!(!issues.iter().any(|i| i.rule_id == "QUAL-DEAD-001"));
    }

    #[test]
    fn duplicate_queries_in_examples_are_skipped() {
        let mut result = AnalysisResult::new();

        let mut q1 = Query {
            raw: "SELECT id FROM users".to_string(),
            normalized: "SELECT id FROM users".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("project/examples/a.sql"),
            query_type: Some("SELECT".to_string()),
            ..Default::default()
        };
        q1.normalized = "SELECT id FROM users".to_string();

        let mut q2 = Query {
            raw: "SELECT id FROM users".to_string(),
            normalized: "SELECT id FROM users".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1).with_file("project/examples/b.sql"),
            query_type: Some("SELECT".to_string()),
            ..Default::default()
        };
        q2.normalized = "SELECT id FROM users".to_string();

        result.queries.push(q1);
        result.queries.push(q2);

        let issues = detect_duplicate_queries(&result);
        assert!(issues.is_empty());
    }

    #[test]
    fn infer_context_additional_paths() {
        assert_eq!(infer_context_from_path("project/docs/query.sql"), "example");
        assert_eq!(infer_context_from_path("project/script/run.sql"), "example");
        assert_eq!(infer_context_from_path("db/structure.sql"), "ddl_schema");
        assert_eq!(infer_context_from_path("seed/data.sql"), "seed");
        assert_eq!(
            infer_context_from_path("lib/connection_adapter/postgres.rb"),
            "framework_internal"
        );
    }
}
