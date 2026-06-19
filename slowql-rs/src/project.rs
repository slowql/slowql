//! Project-level analysis: cross-file breaking changes, dead SQL detection,
//! and duplicate query detection. Operates on the combined set of all parsed
//! queries after individual file analysis is complete.

use std::collections::{HashMap, HashSet};
use crate::models::{Dimension, Issue, Severity};
use crate::models::issue::{Category, Location, RuleConfidence};
use crate::models::result::AnalysisResult;

/// Run all project-level checks on the combined analysis result.
/// Returns additional issues to append.
pub fn analyze_project(result: &AnalysisResult) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(detect_cross_file_breaks(result));
    issues.extend(detect_unused_objects(result));
    issues.extend(detect_duplicate_queries(result));
    issues
}

/// SCH-BRK-001: Detect when a DROP COLUMN or DROP TABLE in one file
/// breaks a reference in another file.
fn detect_cross_file_breaks(result: &AnalysisResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Collect all dropped tables and columns
    let mut dropped_tables: Vec<(String, String)> = Vec::new(); // (table, file)
    let mut dropped_columns: Vec<(String, String, String)> = Vec::new(); // (table, column, file)

    for query in &result.queries {
        let upper = query.raw_upper();
        let file = query.location.file.as_deref().unwrap_or("");

        if upper.contains("DROP TABLE") {
            // Extract table name after DROP TABLE [IF EXISTS]
            if let Some(name) = extract_drop_table_name(&upper) {
                dropped_tables.push((name, file.to_string()));
            }
        }

        if upper.contains("DROP COLUMN") {
            // Extract table and column from ALTER TABLE x DROP COLUMN y
            if let Some((table, col)) = extract_drop_column(&upper) {
                dropped_columns.push((table, col, file.to_string()));
            }
        }
    }

    // Check all queries for references to dropped tables/columns
    for query in &result.queries {
        let file = query.location.file.as_deref().unwrap_or("");

        for (dropped_table, drop_file) in &dropped_tables {
            if file == drop_file { continue; } // same file is not cross-file
            // Skip same-directory files (likely dialect variants like h2.sql, mysql.sql, pg.sql)
            let file_dir = file.rsplit('/').nth(1).unwrap_or("");
            let drop_dir = drop_file.rsplit('/').nth(1).unwrap_or("");
            if !file_dir.is_empty() && file_dir == drop_dir { continue; }
            // Skip when both files are in a directory structure that suggests
            // they are dialect variants (e.g., v1/h2-foo.sql and v1/mysql-foo.sql)
            let file_name = file.rsplit('/').next().unwrap_or("");
            let drop_name = drop_file.rsplit('/').next().unwrap_or("");
            let dialect_prefixes = ["h2-", "mysql-", "postgres-", "postgresql-",
                "mariadb-", "sqlite-", "oracle-", "mssql-", "tsql-",
                "redshift-", "snowflake-", "bigquery-", "clickhouse-",
                "duckdb-", "presto-", "trino-", "spark-", "databricks-"];
            let file_is_dialect = dialect_prefixes.iter().any(|p| file_name.starts_with(p));
            let drop_is_dialect = dialect_prefixes.iter().any(|p| drop_name.starts_with(p));
            if file_is_dialect || drop_is_dialect { continue; }
            // Skip when both files are under a migrations/ or initialization/ directory.
            // Migration files contain intentional destructive DDL.
            let file_lower = file.to_lowercase();
            let drop_lower = drop_file.to_lowercase();
            if (file_lower.contains("/migrations/") || file_lower.contains("/initialization/"))
                && (drop_lower.contains("/migrations/") || drop_lower.contains("/initialization/")) {
                continue;
            }
            let lower_table = dropped_table.to_lowercase();
            if query.tables.iter().any(|t| t.to_lowercase() == lower_table) {
                let msg = format!(
                    "Cross-file breaking change: table '{}' is dropped in {} but referenced here.",
                    dropped_table, short_path(drop_file)
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

        for (dropped_table, dropped_col, drop_file) in &dropped_columns {
            if file == drop_file { continue; }
            let lower_table = dropped_table.to_lowercase();
            let lower_col = dropped_col.to_lowercase();
            if query.tables.iter().any(|t| t.to_lowercase() == lower_table) {
                if query.columns.iter().any(|c| c.to_lowercase() == lower_col) {
                    let msg = format!(
                        "Cross-file breaking change: column '{}.{}' is dropped in {} but referenced here.",
                        dropped_table, dropped_col, short_path(drop_file)
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

    issues
}

/// QUAL-DEAD-001: Detect CREATE VIEW/FUNCTION/PROCEDURE that are never
/// referenced by any other query in the project.
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
        for keyword in &["CREATE VIEW", "CREATE OR REPLACE VIEW",
                         "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION",
                         "CREATE PROCEDURE", "CREATE OR REPLACE PROCEDURE"] {
            if upper.contains(keyword) {
                if let Some(name) = extract_object_name(&upper, keyword) {
                    defined.push((keyword.to_string(), name, query.location.clone(), file.clone()));
                }
            }
        }

        // Collect all table/view references
        for table in &query.tables {
            referenced.insert(table.to_lowercase());
        }

        // Also check raw SQL for function/procedure calls
        let raw_lower = query.raw_lower().to_string();
        // Simple heuristic: any identifier followed by ( is a function call
        for word in raw_lower.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if !word.is_empty() && raw_lower.contains(&format!("{}(", word)) {
                referenced.insert(word.to_string());
            }
        }
    }

    for (obj_type, name, location, _file) in &defined {
        let lower_name = name.to_lowercase();
        // Strip schema prefix for matching
        let base_name = lower_name.rsplit('.').next().unwrap_or(&lower_name);
        if !referenced.contains(base_name) {
            let msg = format!(
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
        if query.normalized.is_empty() { continue; }
        // Skip DDL and admin queries
        let qt = query.query_type.as_deref().unwrap_or("");
        if !matches!(qt, "SELECT" | "INSERT" | "UPDATE" | "DELETE") { continue; }
        // Skip non-production queries (test, example, seed)
        let file = query.location.file.as_deref().unwrap_or("");
        if file.contains("/test/") || file.contains("/tests/")
            || file.contains("/spec/") || file.contains("/examples/")
            || file.contains("/fixtures/") || file.contains("/__tests__/")
        {
            continue;
        }

        let key = query.normalized.to_uppercase();
        seen.entry(key).or_default().push(query.location.clone());
    }

    for (normalized, locations) in &seen {
        if locations.len() < 2 { continue; }
        // Only report at the second occurrence
        for loc in &locations[1..] {
            let first_file = locations[0].file.as_deref().unwrap_or("unknown");
            let msg = format!(
                "Duplicate query detected. Same query also appears at {}:{}.",
                short_path(first_file), locations[0].line
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
            issue.source_context = infer_context_from_path(
                loc.file.as_deref().unwrap_or("")
            );
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
    let after = if after.starts_with("IF EXISTS") {
        after["IF EXISTS".len()..].trim_start()
    } else {
        after
    };
    let name = after.split(|c: char| c.is_whitespace() || c == ';' || c == '(')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');
    if name.is_empty() { None } else { Some(name.to_string()) }
}

fn extract_drop_column(upper: &str) -> Option<(String, String)> {
    let idx = upper.find("ALTER TABLE")?;
    let after = &upper[idx + "ALTER TABLE".len()..].trim_start();
    let table = after.split_whitespace().next()?
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');

    let col_idx = upper.find("DROP COLUMN")?;
    let after_col = &upper[col_idx + "DROP COLUMN".len()..].trim_start();
    let col = after_col.split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');

    if table.is_empty() || col.is_empty() { None } else { Some((table.to_string(), col.to_string())) }
}

fn extract_object_name(upper: &str, keyword: &str) -> Option<String> {
    let idx = upper.find(keyword)?;
    let after = &upper[idx + keyword.len()..].trim_start();
    let name = after.split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == '"' || c == '`' || c == '[' || c == ']');
    if name.is_empty() || name == "AS" { None } else { Some(name.to_string()) }
}

fn infer_context_from_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.contains("/test/") || lower.contains("/tests/")
        || lower.contains("/spec/") || lower.contains("/__tests__/")
        || lower.contains("/e2e/") || lower.contains(".spec.")
        || lower.contains(".test.") || lower.contains("/test_resources/")
        || lower.contains("/test-resources/") {
        "test".to_string()
    } else if lower.contains("/migration/") || lower.contains("/migrations/")
        || lower.contains("/db/migrate/") {
        "migration".to_string()
    } else if lower.contains("/example/") || lower.contains("/examples/")
        || lower.contains("/doc/") || lower.contains("/docs/")
        || lower.contains("/demo/") || lower.contains("/scripts/")
        || lower.contains("/script/") {
        "example".to_string()
    } else if lower.contains("/seed/") || lower.contains("/seeds/")
        || lower.contains("/fixtures/") || lower.ends_with("/seed.sql")
        || lower.ends_with("/data.sql") {
        "seed".to_string()
    } else if lower.contains("/connection_adapter") || lower.contains("/db/backends/")
        || lower.contains("/db/models/sql/") || lower.contains("/lib/arel/")
        || lower.contains("/activerecord/lib/") {
        "framework_internal".to_string()
    } else if lower.ends_with("/structure.sql") || lower.ends_with("/schema.sql")
        || lower.contains("/schema/") || lower.contains("/ddl/") {
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
                sql.trim().split_whitespace().next().unwrap_or("SELECT").to_uppercase()
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
        result.queries.push(make_query("DROP TABLE users", "migrations/001.sql"));
        result.queries.push(make_query("SELECT id, name FROM users WHERE id = 1", "src/app.sql"));

        let issues = analyze_project(&result);
        assert!(issues.iter().any(|i| i.rule_id == "SCH-BRK-001"),
            "should detect cross-file break when DROP TABLE and SELECT reference same table");
    }

    #[test]
    fn same_file_drop_not_cross_file() {
        let mut result = AnalysisResult::new();
        result.queries.push(make_query("DROP TABLE temp_data", "cleanup.sql"));
        result.queries.push(make_query("CREATE TABLE temp_data (id INT)", "cleanup.sql"));

        let issues = analyze_project(&result);
        assert!(!issues.iter().any(|i| i.rule_id == "SCH-BRK-001"),
            "same-file DROP should not be flagged as cross-file break");
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
        assert!(issues.iter().any(|i| i.rule_id == "QUAL-DEAD-003"),
            "should detect duplicate queries across files");
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
        assert!(!issues.iter().any(|i| i.rule_id == "QUAL-DEAD-003"),
            "different queries should not be flagged as duplicates");
    }
}
