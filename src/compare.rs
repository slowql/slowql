//! Query comparison mode: detect structurally similar queries that
//! could be consolidated, and highlight differences between query variants.

use crate::models::query::Query;
use crate::models::issue::{Issue, Category, RuleConfidence};
use crate::models::{Dimension, Severity};
use std::collections::HashMap;

/// Compare all queries and find similar ones that differ only in constants.
pub fn find_similar_queries(queries: &[Query]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut buckets: HashMap<String, Vec<(usize, &Query)>> = HashMap::new();

    for (idx, query) in queries.iter().enumerate() {
        let qt = query.query_type.as_deref().unwrap_or("");
        if !matches!(qt, "SELECT" | "INSERT" | "UPDATE" | "DELETE") {
            continue;
        }

        let skeleton = normalize_to_skeleton(&query.raw);
        if skeleton.len() < 20 {
            continue;
        }
        buckets.entry(skeleton).or_default().push((idx, query));
    }

    for (_skeleton, group) in &buckets {
        if group.len() < 2 {
            continue;
        }

        // Check if the queries come from different files
        let files: std::collections::HashSet<&str> = group.iter()
            .filter_map(|(_, q)| q.location.file.as_deref())
            .collect();

        if files.len() < 2 {
            continue;
        }

        let first = group[0].1;
        for &(_, query) in &group[1..] {
            let first_file = first.location.file.as_deref().unwrap_or("unknown");
            let msg = format!(
                "Similar query found at {}:{}. Consider extracting to a shared query.",
                short_path(first_file), first.location.line
            );
            let mut issue = Issue::new(
                "QUAL-COMPARE-001",
                msg,
                Severity::Info,
                Dimension::Quality,
                query.location.clone(),
                query.snippet(80),
            );
            issue.category = Some(Category::QualDry);
            issue.confidence = RuleConfidence::Advisory;
            issues.push(issue);
        }
    }

    issues
}

/// Normalize a query to a skeleton by replacing all literal values
/// with placeholders. This makes structurally identical queries
/// with different constants match each other.
fn normalize_to_skeleton(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            // Replace string literals with ?
            '\'' => {
                result.push('?');
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\'' {
                        i += 1;
                        if i < chars.len() && chars[i] == '\'' {
                            i += 1;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            // Replace numeric literals with ?
            c if c.is_ascii_digit() => {
                // Check if this is part of an identifier
                if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
                    result.push(c);
                    i += 1;
                } else {
                    result.push('?');
                    while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                        i += 1;
                    }
                }
            }
            // Normalize whitespace
            c if c.is_whitespace() => {
                if !result.ends_with(' ') {
                    result.push(' ');
                }
                i += 1;
            }
            // Uppercase keywords
            c => {
                result.push(c.to_ascii_uppercase());
                i += 1;
            }
        }
    }

    result.trim().to_string()
}

fn short_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Location;

    #[test]
    fn skeleton_normalizes_literals() {
        let s1 = normalize_to_skeleton("SELECT * FROM users WHERE id = 42");
        let s2 = normalize_to_skeleton("SELECT * FROM users WHERE id = 99");
        assert_eq!(s1, s2);
    }

    #[test]
    fn skeleton_normalizes_strings() {
        let s1 = normalize_to_skeleton("SELECT * FROM users WHERE name = 'alice'");
        let s2 = normalize_to_skeleton("SELECT * FROM users WHERE name = 'bob'");
        assert_eq!(s1, s2);
    }

    #[test]
    fn skeleton_preserves_structure() {
        let s1 = normalize_to_skeleton("SELECT * FROM users WHERE id = 1");
        let s2 = normalize_to_skeleton("SELECT * FROM orders WHERE id = 1");
        assert_ne!(s1, s2);
    }

    #[test]
    fn find_similar_across_files() {
        let q1 = Query {
            raw: "SELECT * FROM users WHERE id = 1".to_string(),
            normalized: "SELECT * FROM users WHERE id = 1".to_string(),
            query_type: Some("SELECT".to_string()),
            location: Location::new(1, 1).with_file("src/a.sql"),
            ..Default::default()
        };
        let q2 = Query {
            raw: "SELECT * FROM users WHERE id = 42".to_string(),
            normalized: "SELECT * FROM users WHERE id = 42".to_string(),
            query_type: Some("SELECT".to_string()),
            location: Location::new(1, 1).with_file("src/b.sql"),
            ..Default::default()
        };
        let issues = find_similar_queries(&[q1, q2]);
        assert!(!issues.is_empty(), "should detect similar queries across files");
    }

    #[test]
    fn no_false_similar_same_file() {
        let q1 = Query {
            raw: "SELECT * FROM users WHERE id = 1".to_string(),
            normalized: "SELECT * FROM users WHERE id = 1".to_string(),
            query_type: Some("SELECT".to_string()),
            location: Location::new(1, 1).with_file("src/a.sql"),
            ..Default::default()
        };
        let q2 = Query {
            raw: "SELECT * FROM users WHERE id = 42".to_string(),
            normalized: "SELECT * FROM users WHERE id = 42".to_string(),
            query_type: Some("SELECT".to_string()),
            location: Location::new(5, 1).with_file("src/a.sql"),
            ..Default::default()
        };
        let issues = find_similar_queries(&[q1, q2]);
        assert!(issues.is_empty(), "same-file similar queries should not flag");
    }
}
