use crate::models::issue::{Category, Fix};
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

// QUAL-STYLE-001
struct SelectWithoutFromRule;
static PAT_NO_FROM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*SELECT\b").unwrap());
impl Rule for SelectWithoutFromRule {
    fn id(&self) -> &'static str {
        "QUAL-STYLE-001"
    }
    fn name(&self) -> &'static str {
        "SELECT Without FROM Clause"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "Constant SELECT statements may indicate debug code."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }

        if PAT_NO_FROM.is_match(&query.raw) && !query.raw_upper().contains("FROM") {
            return vec![self.build_issue(
                query,
                "SELECT without FROM detected - verify intentional.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

// QUAL-STYLE-002
struct WildcardInColumnListRule;
static PAT_EXISTS_STAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bEXISTS\s*\(\s*SELECT\s+\*").unwrap());
impl Rule for WildcardInColumnListRule {
    fn id(&self) -> &'static str {
        "QUAL-STYLE-002"
    }
    fn name(&self) -> &'static str {
        "Wildcard in EXISTS Subquery"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "SELECT * in EXISTS may prevent optimizer shortcuts."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_EXISTS_STAR
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "SELECT * inside EXISTS subquery - use SELECT 1 instead.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// QUAL-STYLE-003
struct MissingAliasRule;
static PAT_NO_ALIAS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bFROM\s*\(\s*SELECT\b[^)]+\)\s*WHERE\b").unwrap());
impl Rule for MissingAliasRule {
    fn id(&self) -> &'static str {
        "QUAL-STYLE-003"
    }
    fn name(&self) -> &'static str {
        "Subquery Missing Alias"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "Unaliased subqueries cause syntax errors in PostgreSQL and MySQL."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_NO_ALIAS
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Subquery in FROM without alias detected.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// QUAL-STYLE-004
struct CommentedCodeRule;
static PAT_COMMENTED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)--\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b").unwrap()
});
impl Rule for CommentedCodeRule {
    fn id(&self) -> &'static str {
        "QUAL-STYLE-004"
    }
    fn name(&self) -> &'static str {
        "Commented-Out SQL Code"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "Commented-out code creates confusion and bloats query logs."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_COMMENTED
            .find(&query.raw)
            .map(|m| vec![self.build_issue(query, "Commented-out SQL code detected.", m.as_str())])
            .unwrap_or_default()
    }
}

// QUAL-STYLE-005
struct InsertWithoutColumnListRule;
impl Rule for InsertWithoutColumnListRule {
    fn id(&self) -> &'static str {
        "QUAL-STYLE-005"
    }
    fn name(&self) -> &'static str {
        "INSERT Without Column List"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "A schema change silently shifts all values one position."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_insert() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if !upper.contains("VALUES") {
            return Vec::new();
        }

        let after_into = match upper.find("INSERT INTO") {
            Some(pos) => &query.raw[pos + "INSERT INTO".len()..],
            None => return Vec::new(),
        };

        let values_pos = match after_into.to_uppercase().find("VALUES") {
            Some(pos) => pos,
            None => return Vec::new(),
        };

        let before_values = after_into[..values_pos].trim();

        if before_values.contains('(') && before_values.contains(')') {
            return Vec::new();
        }

        vec![self.build_issue(
            query,
            "INSERT without column list - fragile if schema changes.",
            query.snippet(80),
        )]
    }
}

// QUAL-NULL-001
struct NullComparisonRule;
static PAT_NULL_CMP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:[^!<>])=\s*NULL\b|!=\s*NULL\b|<>\s*NULL\b").unwrap());
impl Rule for NullComparisonRule {
    fn id(&self) -> &'static str {
        "QUAL-NULL-001"
    }
    fn name(&self) -> &'static str {
        "Incorrect NULL Comparison"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "Using = NULL silently returns zero rows."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_NULL_CMP
            .find(&query.raw)
            .map(|m| {
                let matched = m.as_str();
                let matched_pos = m.start();
                let raw = &query.raw;
                // Only flag = NULL in WHERE/HAVING/ON context.
                // SET col = NULL is valid SQL to explicitly null a column.
                // Check if this match is inside a SET clause by looking backwards.
                let before = raw[..matched_pos].to_uppercase();
                let set_pos = before.rfind("SET ");
                let where_pos = before.rfind("WHERE ");
                let having_pos = before.rfind("HAVING ");
                let on_pos = before.rfind(" ON ");
                // If the nearest prior context keyword is SET, this is a SET clause
                let nearest_context = [set_pos, where_pos, having_pos, on_pos]
                    .iter()
                    .filter_map(|&p| p)
                    .max();
                if nearest_context == set_pos && set_pos.is_some() {
                    return vec![];
                }
                let (orig, repl) = if matched.contains("!=") || matched.contains("<>") {
                    (
                        matched.to_string(),
                        matched.replace("!=", "IS NOT").replace("<>", "IS NOT"),
                    )
                } else {
                    (
                        matched.to_string(),
                        matched.replace("=", "IS").replace("  ", " "),
                    )
                };
                vec![self.build_issue_with_fix(
                    query,
                    "Incorrect NULL comparison - use IS NULL or IS NOT NULL.",
                    matched,
                    Fix::safe("Replace with IS NULL / IS NOT NULL", orig, repl, self.id()),
                )]
            })
            .unwrap_or_default()
    }
}

// QUAL-MODERN-001
struct ImplicitJoinRule;
static PAT_IMPLICIT_JOIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)FROM\s+\w+\s*,\s*\w+").unwrap());
impl Rule for ImplicitJoinRule {
    fn id(&self) -> &'static str {
        "QUAL-MODERN-001"
    }
    fn name(&self) -> &'static str {
        "Implicit Join Syntax"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn impact(&self) -> &'static str {
        "Implicit joins are harder to read and prone to accidental cross-joins."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if PAT_IMPLICIT_JOIN.is_match(&query.raw) && !query.raw_upper().contains("JOIN") {
            return vec![self.build_issue(
                query,
                "Implicit join syntax detected (comma-separated tables).",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

// QUAL-MODERN-002
struct HardcodedDateRule;
static PAT_DATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bWHERE\b.+['"](\d{4}-\d{2}-\d{2})['"]"#).unwrap());
impl Rule for HardcodedDateRule {
    fn id(&self) -> &'static str {
        "QUAL-MODERN-002"
    }
    fn name(&self) -> &'static str {
        "Hardcoded Date Literal in Filter"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn impact(&self) -> &'static str {
        "Hardcoded dates become stale and cause queries to return unexpected results."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        PAT_DATE
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(query, "Hardcoded date literal in WHERE clause.", m.as_str())]
            })
            .unwrap_or_default()
    }
}

// QUAL-MODERN-003
struct UnionWithoutAllRule;
impl Rule for UnionWithoutAllRule {
    fn id(&self) -> &'static str {
        "QUAL-MODERN-003"
    }
    fn name(&self) -> &'static str {
        "UNION Without ALL"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn impact(&self) -> &'static str {
        "UNION deduplicates using expensive sort or hash."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Manually check: find UNION not followed by ALL
        let upper = query.raw_upper();
        if !upper.contains("UNION") {
            return Vec::new();
        }
        // Simple: if has UNION but not UNION ALL
        if upper.contains("UNION ALL") {
            return Vec::new();
        }
        if upper.contains("UNION") {
            return vec![self.build_issue(
                query,
                "UNION without ALL - use UNION ALL if duplicates are not a concern.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

// QUAL-MODERN-004
struct CaseWithoutElseRule;
impl Rule for CaseWithoutElseRule {
    fn id(&self) -> &'static str {
        "QUAL-MODERN-004"
    }
    fn name(&self) -> &'static str {
        "CASE Without ELSE"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn impact(&self) -> &'static str {
        "Unmatched CASE returns NULL, which propagates through calculations."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("CASE") || !upper.contains("WHEN") {
            return Vec::new();
        }
        if upper.contains("ELSE") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "CASE without ELSE - returns NULL when no condition matches.",
            query.snippet(80),
        )]
    }
}

// QUAL-DRY-001
struct DuplicateConditionRule;
static PAT_DUP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.+\bAND\b").unwrap());
impl Rule for DuplicateConditionRule {
    fn id(&self) -> &'static str {
        "QUAL-DRY-001"
    }
    fn name(&self) -> &'static str {
        "Duplicate WHERE Condition"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualDry)
    }
    fn impact(&self) -> &'static str {
        "Duplicate conditions waste parser cycles and obscure intent."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        // Check for duplicate conditions: col = val AND col = val
        if !PAT_DUP.is_match(&query.raw) {
            return Vec::new();
        }
        let lower = query.raw_lower();
        // Extract conditions around AND
        let parts: Vec<&str> = lower.split(" and ").collect();
        for i in 0..parts.len() {
            for j in (i + 1)..parts.len() {
                let a = parts[i].trim();
                let b = parts[j].trim();
                if !a.is_empty() && a == b {
                    return vec![self.build_issue(
                        query,
                        "Duplicate WHERE condition detected - possible copy-paste error.",
                        query.snippet(80),
                    )];
                }
            }
        }
        Vec::new()
    }
}

// QUAL-COMPLEX-001..005
struct ExcessiveCaseNestingRule;
impl Rule for ExcessiveCaseNestingRule {
    fn id(&self) -> &'static str {
        "QUAL-COMPLEX-001"
    }
    fn name(&self) -> &'static str {
        "Excessive CASE Nesting"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualComplexity)
    }
    fn impact(&self) -> &'static str {
        "Deeply nested CASE statements are difficult to understand and test."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        let case_count = upper.matches("CASE").count();
        if case_count > 3 {
            let msg = format!("CASE expression nested {} levels deep.", case_count);
            return vec![self.build_issue(query, &msg, query.snippet(100))];
        }
        Vec::new()
    }
}

struct ExcessiveSubqueryNestingRule;
impl Rule for ExcessiveSubqueryNestingRule {
    fn id(&self) -> &'static str {
        "QUAL-COMPLEX-002"
    }
    fn name(&self) -> &'static str {
        "Excessive Subquery Nesting"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualComplexity)
    }
    fn impact(&self) -> &'static str {
        "Deeply nested subqueries are unreadable and hard to optimize."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let count = query.raw_upper().matches("(SELECT").count();
        if count >= 3 {
            let msg = format!("Subquery nested {} levels deep.", count);
            return vec![self.build_issue(query, &msg, query.snippet(100))];
        }
        Vec::new()
    }
}

struct GodQueryRule;
impl Rule for GodQueryRule {
    fn id(&self) -> &'static str {
        "QUAL-COMPLEX-003"
    }
    fn name(&self) -> &'static str {
        "God Query"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualComplexity)
    }
    fn impact(&self) -> &'static str {
        "God queries are slow, hard to optimize, impossible to test."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        let score = upper.matches("JOIN").count() * 2
            + upper.matches(" AND ").count()
            + upper.matches(" OR ").count()
            + upper.matches("(SELECT").count() * 3;
        if score > 25 {
            let msg = format!("God query detected (complexity score: {}).", score);
            return vec![self.build_issue(query, &msg, query.snippet(100))];
        }
        Vec::new()
    }
}

struct CyclomaticComplexityRule;
static PAT_CYCLO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)\b(CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE|CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION)\b",
    )
    .unwrap()
});
impl Rule for CyclomaticComplexityRule {
    fn id(&self) -> &'static str {
        "QUAL-COMPLEX-004"
    }
    fn name(&self) -> &'static str {
        "Cyclomatic Complexity in Stored Procedure"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualComplexity)
    }
    fn impact(&self) -> &'static str {
        "High cyclomatic complexity means many code paths, making testing exponentially harder."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !PAT_CYCLO.is_match(&query.raw) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        let branches = upper.matches("IF ").count()
            + upper.matches("WHILE ").count()
            + upper.matches("CASE ").count();
        if branches >= 5 {
            return vec![self.build_issue(
                query,
                "Stored procedure with high cyclomatic complexity.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

struct LongQueryRule;
impl Rule for LongQueryRule {
    fn id(&self) -> &'static str {
        "QUAL-COMPLEX-005"
    }
    fn name(&self) -> &'static str {
        "Long Query (Line Count)"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualComplexity)
    }
    fn impact(&self) -> &'static str {
        "Queries over 50 lines are hard to understand, review, and debug."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let lines = query.raw.chars().filter(|&c| c == '\n').count() + 1;
        if lines > 50 {
            let msg = format!(
                "Query is {} lines long - consider breaking into smaller queries.",
                lines
            );
            return vec![self.build_issue(query, &msg, query.snippet(100))];
        }
        Vec::new()
    }
}

// QUAL-NAME-001..004
struct InconsistentTableNamingRule;
// Words that end in s/ss/es but are not plural forms
static SINGULAR_EXCEPTIONS: &[&str] = &[
    "address",
    "access",
    "process",
    "progress",
    "business",
    "class",
    "status",
    "canvas",
    "axis",
    "basis",
    "crisis",
    "analysis",
    "diagnosis",
    "hypothesis",
    "bus",
    "virus",
    "lens",
    "atlas",
    "bonus",
    "campus",
    "census",
    "focus",
    "nexus",
    "radius",
    "stimulus",
    "surplus",
    "alias",
    "pass",
    "chess",
    "congress",
    "express",
    "stress",
    "success",
    "witness",
];
impl Rule for InconsistentTableNamingRule {
    fn id(&self) -> &'static str {
        "QUAL-NAME-001"
    }
    fn name(&self) -> &'static str {
        "Inconsistent Table Naming"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualNaming)
    }
    fn impact(&self) -> &'static str {
        "Inconsistent naming makes the schema harder to learn and navigate."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.tables.len() < 2 {
            return Vec::new();
        }
        // Classify each table as singular or plural, accounting for exceptions
        let mut singular_count = 0;
        let mut plural_count = 0;
        for t in &query.tables {
            let lower = t.to_lowercase();
            // Strip schema prefix if present (e.g., public.users -> users)
            let name = lower.rsplit('.').next().unwrap_or(&lower);
            // Words that are ambiguous (end in s/ss/es naturally) are excluded
            // from the count entirely. They should not be evidence of either convention.
            if SINGULAR_EXCEPTIONS
                .iter()
                .any(|ex| name == *ex || name.ends_with(&format!("_{}", ex)))
            {
                continue; // ambiguous, skip
            } else if name.ends_with("ies")
                || (name.ends_with('s') && !name.ends_with("ss") && !name.ends_with("us"))
            {
                plural_count += 1;
            } else {
                singular_count += 1;
            }
        }
        if singular_count > 0 && plural_count > 0 {
            return vec![self.build_issue(
                query,
                "Inconsistent table naming: mixed singular and plural names.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct AmbiguousAliasRule;
static PAT_ALIAS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:AS|FROM|JOIN)\s+([a-z])").unwrap());
impl Rule for AmbiguousAliasRule {
    fn id(&self) -> &'static str {
        "QUAL-NAME-002"
    }
    fn name(&self) -> &'static str {
        "Ambiguous Alias"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualNaming)
    }
    fn impact(&self) -> &'static str {
        "Single-letter aliases make complex queries impossible to read."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_ALIAS
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(query, "Ambiguous single-letter alias detected.", m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct HungarianNotationRule;
static PAT_HUNGARIAN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(str_|int_|i_|tbl_|v_)[a-z0-9_]+\b").unwrap());
impl Rule for HungarianNotationRule {
    fn id(&self) -> &'static str {
        "QUAL-NAME-003"
    }
    fn name(&self) -> &'static str {
        "Hungarian Notation in Names"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualNaming)
    }
    fn impact(&self) -> &'static str {
        "Hungarian notation is redundant in SQL as types are defined in schema."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_HUNGARIAN
            .find(&query.raw)
            .map(|m| vec![self.build_issue(query, "Hungarian notation detected.", m.as_str())])
            .unwrap_or_default()
    }
}

struct ReservedWordAsColumnRule;
static RESERVED: &[&str] = &[
    "ORDER", "GROUP", "TABLE", "INDEX", "USER", "DATE", "KEY", "COLUMN", "LIMIT", "OFFSET",
];
impl Rule for ReservedWordAsColumnRule {
    fn id(&self) -> &'static str {
        "QUAL-NAME-004"
    }
    fn name(&self) -> &'static str {
        "Reserved Word as Identifier"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualNaming)
    }
    fn impact(&self) -> &'static str {
        "Using reserved words forces double quotes and can lead to syntax errors."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        for col in &query.columns {
            if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(col)) {
                let msg = format!("Reserved word '{}' used as identifier.", col.to_uppercase());
                return vec![self.build_issue(query, &msg, col)];
            }
        }
        Vec::new()
    }
}

// QUAL-DOC-001..003
struct MissingColumnCommentsRule;
static PAT_CREATE_NO_COMMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)CREATE\s+TABLE\b").unwrap());
impl Rule for MissingColumnCommentsRule {
    fn id(&self) -> &'static str {
        "QUAL-DOC-001"
    }
    fn name(&self) -> &'static str {
        "Missing Column Comments"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualDocumentation)
    }
    fn impact(&self) -> &'static str {
        "Missing comments mean business meaning must be reverse-engineered."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if query.raw_upper().contains(" AS SELECT") {
            return Vec::new();
        }
        if query.raw_upper().contains(" AS SELECT") {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if PAT_CREATE_NO_COMMENT.is_match(&query.raw) && !query.raw_upper().contains("COMMENT") {
            return vec![self.build_issue(
                query,
                "CREATE TABLE without column comments.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct MagicStringWithoutCommentRule;
static PAT_MAGIC: Lazy<Regex> = Lazy::new(|| {
    // Match WHERE ... column = 'value' capturing column name and value
    Regex::new(r#"(?i)\bWHERE\b.*?\b([a-zA-Z_][\w]*)\b\s*=\s*'([^']+)'"#).unwrap()
});
static PAT_MAGIC_UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});
static PAT_MAGIC_DATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap());
// Columns that typically hold business classification enums.
// Only flag magic constants on these columns.
static MAGIC_DOC_COLUMNS: &[&str] = &[
    "status",
    "state",
    "type",
    "role",
    "category",
    "kind",
    "code",
    "flag",
    "mode",
    "level",
    "tier",
    "plan",
    "channel",
    "source",
    "reason",
    "provider",
    "environment",
    "priority",
    "severity",
];
// Common enum values that are self-documenting and do not need a comment.
static MAGIC_COMMON_VALUES: &[&str] = &[
    "active",
    "inactive",
    "pending",
    "completed",
    "true",
    "false",
    "yes",
    "no",
    "enabled",
    "disabled",
    "open",
    "closed",
    "draft",
    "published",
    "archived",
    "deleted",
    "admin",
    "user",
    "guest",
    "paid",
    "unpaid",
    "cancelled",
    "approved",
    "rejected",
    "shipped",
    "delivered",
    "processing",
    "failed",
    "success",
    "error",
    "public",
    "private",
    "default",
    "system",
    "test",
    "dev",
    "prod",
    "staging",
    "new",
    "old",
    "unknown",
    "other",
    "none",
    "confirmed",
    "unconfirmed",
    "blocked",
    "suspended",
    "expired",
    "verified",
];

impl Rule for MagicStringWithoutCommentRule {
    fn id(&self) -> &'static str {
        "QUAL-DOC-002"
    }
    fn name(&self) -> &'static str {
        "Magic Constant Without Comment"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualDocumentation)
    }
    fn impact(&self) -> &'static str {
        "Magic constants represent opaque business logic."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        // Already commented queries do not need this rule
        if query.raw.contains("--") || query.raw.contains("/*") {
            return Vec::new();
        }
        // Skip dynamic SQL where concatenation is the real problem
        if query.is_dynamic
            || query.raw.contains("||")
            || query.raw.contains("CONCAT(")
            || query.raw.contains(" + ")
        {
            return Vec::new();
        }

        let caps = match PAT_MAGIC.captures(&query.raw) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let column = caps
            .get(1)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();
        let value = caps
            .get(2)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();

        // Only flag when column is a known business classification field
        let is_doc_column = MAGIC_DOC_COLUMNS
            .iter()
            .any(|c| column == *c || column.ends_with(&format!("_{}", c)));
        if !is_doc_column {
            return Vec::new();
        }

        // Skip trivially short values (likely placeholders)
        if value.len() <= 1 {
            return Vec::new();
        }
        // Skip values that are obviously not business constants
        if value.contains('@')
            || value.contains("://")
            || value.contains('/')
            || value.contains('\\')
        {
            return Vec::new();
        }
        if PAT_MAGIC_UUID.is_match(&value) || PAT_MAGIC_DATE.is_match(&value) {
            return Vec::new();
        }
        // Skip common self-documenting enum values
        if MAGIC_COMMON_VALUES.iter().any(|cv| *cv == value) {
            return Vec::new();
        }

        let snippet = caps.get(0).map(|m| m.as_str()).unwrap_or(query.snippet(80));
        vec![self.build_issue(query, "Magic constant without comment.", snippet)]
    }
}

struct ComplexLogicWithoutExplanationRule;
impl Rule for ComplexLogicWithoutExplanationRule {
    fn id(&self) -> &'static str {
        "QUAL-DOC-003"
    }
    fn name(&self) -> &'static str {
        "Complex Logic Without Explanation"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualDocumentation)
    }
    fn impact(&self) -> &'static str {
        "Complex queries without comments are prohibitively expensive to modify."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        let score = upper.matches("AND").count()
            + upper.matches("OR").count()
            + upper.matches("CASE").count();
        if score >= 5 && !query.raw.contains("--") && !query.raw.contains("/*") {
            let msg = format!("Complex logic (score: {}) without explanation.", score);
            return vec![self.build_issue(query, &msg, query.snippet(50))];
        }
        Vec::new()
    }
}

// QUAL-SCHEMA-001..004
struct MissingPrimaryKeyRule;
static PAT_CREATE_NO_PK: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)CREATE\s+TABLE\b").unwrap());
impl Rule for MissingPrimaryKeyRule {
    fn id(&self) -> &'static str {
        "QUAL-SCHEMA-001"
    }
    fn name(&self) -> &'static str {
        "Missing Primary Key"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualSchemaDesign)
    }
    fn impact(&self) -> &'static str {
        "Tables without primary keys prevent row uniqueness and break replication."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains(" AS SELECT") {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if !PAT_CREATE_NO_PK.is_match(&query.raw) {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("PRIMARY KEY") {
            return Vec::new();
        }
        // ClickHouse uses ORDER BY as the primary index, not PRIMARY KEY.
        // ENGINE = ... ORDER BY (...) is the ClickHouse equivalent.
        if upper.contains("ORDER BY") && upper.contains("ENGINE") {
            return Vec::new();
        }
        // Skip when table contains placeholders (infrastructure template)
        if query.is_templated() {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "CREATE TABLE without PRIMARY KEY.",
            query.snippet(80),
        )]
    }
}

struct MissingForeignKeyRule;
impl Rule for MissingForeignKeyRule {
    fn id(&self) -> &'static str {
        "QUAL-SCHEMA-002"
    }
    fn name(&self) -> &'static str {
        "Implicit Foreign Key (Logic)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualSchemaDesign)
    }
    fn impact(&self) -> &'static str {
        "Missing foreign keys lead to orphaned records and data corruption."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if query.raw_upper().contains(" AS SELECT") {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        if query.query_type.as_deref() != Some("CREATE") {
            return Vec::new();
        }
        // Only fire on CREATE TABLE, not CREATE INDEX, CREATE SEQUENCE, etc.
        if !query.raw_upper().contains("CREATE TABLE") {
            return Vec::new();
        }
        let lower = query.raw_lower();
        if !lower.contains("_id") {
            return Vec::new();
        }
        if lower.contains("foreign key") || lower.contains("references") {
            return Vec::new();
        }
        vec![self.build_issue(
            query,
            "Column with *_id pattern missing FOREIGN KEY constraint.",
            query.snippet(100),
        )]
    }
}

struct LackOfIndexingOnForeignKeyRule;
impl Rule for LackOfIndexingOnForeignKeyRule {
    fn id(&self) -> &'static str {
        "QUAL-SCHEMA-003"
    }
    fn name(&self) -> &'static str {
        "Missing Index on Foreign Key"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualSchemaDesign)
    }
    fn impact(&self) -> &'static str {
        "JOINs on unindexed foreign keys are extremely slow."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let lower = query.raw_lower();
        if lower.contains("foreign key") && !lower.contains("index") {
            return vec![self.build_issue(
                query,
                "Foreign key without corresponding INDEX.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

struct UsingFloatForCurrencyRule;
static PAT_FLOAT_MONEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(price|amount|balance|cost|total|sum)\b.*?\b(FLOAT|REAL|DOUBLE)\b").unwrap()
});
impl Rule for UsingFloatForCurrencyRule {
    fn id(&self) -> &'static str {
        "QUAL-SCHEMA-004"
    }
    fn name(&self) -> &'static str {
        "Float for Currency"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualSchemaDesign)
    }
    fn impact(&self) -> &'static str {
        "Float types lead to rounding errors catastrophic for financial data."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_FLOAT_MONEY
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Float/Double type for currency - use DECIMAL or NUMERIC.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// QUAL-TEST-001..003
struct NonDeterministicQueryRule;
impl Rule for NonDeterministicQueryRule {
    fn id(&self) -> &'static str {
        "QUAL-TEST-001"
    }
    fn name(&self) -> &'static str {
        "Non-Deterministic Query"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTesting)
    }
    fn impact(&self) -> &'static str {
        "Non-deterministic queries are hard to test and reproduce."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        // LIMIT 0 is an intentional empty-result pattern for metadata queries.
        // Non-deterministic functions in that context are irrelevant.
        if upper.contains("LIMIT 0") {
            return Vec::new();
        }
        let funcs = [
            "NOW(",
            "RAND(",
            "RANDOM(",
            "CURRENT_TIMESTAMP",
            "GETDATE(",
            "CLOCK_TIMESTAMP(",
        ];
        // Only flag if non-deterministic function is in SELECT list, not in WHERE
        if let Some(ref facts) = query.facts {
            if facts.has_where {
                let where_pos = upper.find("WHERE").unwrap_or(upper.len());
                let select_part = &upper[..where_pos];
                if funcs.iter().any(|f| select_part.contains(f)) {
                    return vec![self.build_issue(
                        query,
                        "Non-deterministic function in SELECT list.",
                        query.snippet(80),
                    )];
                }
                return Vec::new();
            }
        }
        if funcs.iter().any(|f| upper.contains(f)) {
            return vec![self.build_issue(
                query,
                "Non-deterministic function detected.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct OrderByMissingForPaginationRule;
impl Rule for OrderByMissingForPaginationRule {
    fn id(&self) -> &'static str {
        "QUAL-TEST-002"
    }
    fn name(&self) -> &'static str {
        "Pagination Without ORDER BY"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTesting)
    }
    fn impact(&self) -> &'static str {
        "Without ORDER BY, pagination can return same row on multiple pages."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("ORDER BY") && upper.contains("OFFSET") {
            return vec![self.build_issue(
                query,
                "OFFSET pagination without ORDER BY - non-deterministic results.",
                query.snippet(100),
            )];
        }
        Vec::new()
    }
}

struct HardcodedTestDataRule;
static PAT_TEST_DATA: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)'[^']*(?:test|dummy|fake|temp|asdf|qwerty)[^']*'"#).unwrap());
impl Rule for HardcodedTestDataRule {
    fn id(&self) -> &'static str {
        "QUAL-TEST-003"
    }
    fn name(&self) -> &'static str {
        "Hardcoded Test Data"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTesting)
    }
    fn impact(&self) -> &'static str {
        "Leftover test data markers indicate poor release hygiene."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TEST_DATA
            .find(&query.raw)
            .map(|m| vec![self.build_issue(query, "Hardcoded test data detected.", m.as_str())])
            .unwrap_or_default()
    }
}

// QUAL-DEBT-001..002
struct TodoFixmeCommentRule;
static PAT_TODO: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(TODO|FIXME|XXX|HACK)\b").unwrap());
impl Rule for TodoFixmeCommentRule {
    fn id(&self) -> &'static str {
        "QUAL-DEBT-001"
    }
    fn name(&self) -> &'static str {
        "Technical Debt Marker"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTechDebt)
    }
    fn impact(&self) -> &'static str {
        "TODO/FIXME markers represent known bugs not tracked in issue tracker."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_TODO
            .find(&query.raw)
            .map(|m| vec![self.build_issue(query, "Technical debt marker detected.", m.as_str())])
            .unwrap_or_default()
    }
}

struct TempTableNotCleanedUpRule;
static PAT_TEMP_NO_DROP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)CREATE\s+(?:TEMPORARY|TEMP)\s+TABLE\s+(\w+)").unwrap());
impl Rule for TempTableNotCleanedUpRule {
    fn id(&self) -> &'static str {
        "QUAL-DEBT-002"
    }
    fn name(&self) -> &'static str {
        "Permanent Temporary Table"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTechDebt)
    }
    fn impact(&self) -> &'static str {
        "Temporary tables not dropped consume memory and disk space."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if let Some(caps) = PAT_TEMP_NO_DROP.captures(&query.raw) {
            let name = caps.get(1).unwrap().as_str();
            if !query
                .raw_upper()
                .contains(&format!("DROP TABLE {}", name.to_uppercase()))
            {
                return vec![self.build_issue(
                    query,
                    "CREATE TEMP TABLE without corresponding DROP TABLE.",
                    caps.get(0).unwrap().as_str(),
                )];
            }
        }
        Vec::new()
    }
}

// QUAL-DEAD-001..003 (project-level rules - basic pattern matching here)
struct UnusedObjectRule;
impl Rule for UnusedObjectRule {
    fn id(&self) -> &'static str {
        "QUAL-DEAD-001"
    }
    fn name(&self) -> &'static str {
        "Unused Database Object"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTechDebt)
    }
    fn impact(&self) -> &'static str {
        "Unused objects clutter the schema."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires project-level analysis */
    }
}
struct UnreachableCodeRule;
impl Rule for UnreachableCodeRule {
    fn id(&self) -> &'static str {
        "QUAL-DEAD-002"
    }
    fn name(&self) -> &'static str {
        "Unreachable Code"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTechDebt)
    }
    fn impact(&self) -> &'static str {
        "Unreachable code after RETURN is dead code."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if !upper.contains("RETURN") {
            return Vec::new();
        }
        if upper.contains("PROCEDURE") || upper.contains("FUNCTION") {
            if let Some(ret_pos) = upper.find("RETURN") {
                let after = &upper[ret_pos + 6..];
                if after.contains("SELECT")
                    || after.contains("UPDATE")
                    || after.contains("INSERT")
                    || after.contains("DELETE")
                {
                    return vec![self.build_issue(
                        query,
                        "Unreachable code after RETURN statement.",
                        query.snippet(100),
                    )];
                }
            }
        }
        Vec::new()
    }
}
struct DuplicateQueryRule;
impl Rule for DuplicateQueryRule {
    fn id(&self) -> &'static str {
        "QUAL-DEAD-003"
    }
    fn name(&self) -> &'static str {
        "Duplicate Query"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualTechDebt)
    }
    fn impact(&self) -> &'static str {
        "Duplicate queries waste resources."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires project-level analysis */
    }
}

// QUAL-DBT-001..002
struct DbtMissingRefRule;
impl Rule for DbtMissingRefRule {
    fn id(&self) -> &'static str {
        "QUAL-DBT-001"
    }
    fn name(&self) -> &'static str {
        "Missing dbt Ref"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn impact(&self) -> &'static str {
        "Hardcoded table names break dbt lineage."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires dbt context */
    }
}
struct DbtHardcodedSchemaRule;
impl Rule for DbtHardcodedSchemaRule {
    fn id(&self) -> &'static str {
        "QUAL-DBT-002"
    }
    fn name(&self) -> &'static str {
        "Hardcoded Schema"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn impact(&self) -> &'static str {
        "Hardcoded schema names break portability."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, _query: &Query) -> Vec<Issue> {
        Vec::new() /* Requires dbt context */
    }
}

// QUAL-PG-002 (JSONB Operator Spacing)
struct JsonbOperatorSpacingRule;
static PAT_JSONB: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(\w+)\s{2,}(->>?|#>>?)").unwrap());
impl Rule for JsonbOperatorSpacingRule {
    fn id(&self) -> &'static str {
        "QUAL-PG-002"
    }
    fn name(&self) -> &'static str {
        "JSONB Operator Spacing"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "Inconsistent spacing reduces readability."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_JSONB
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Inconsistent spacing around JSONB operator.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

// Dialect-specific quality rules
struct RownumWithoutOrderByRule;
static PAT_ROWNUM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bROWNUM\b").unwrap());
impl Rule for RownumWithoutOrderByRule {
    fn id(&self) -> &'static str {
        "QUAL-ORA-001"
    }
    fn name(&self) -> &'static str {
        "ROWNUM Without ORDER BY"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "ROWNUM filters rows BEFORE ORDER BY is applied."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if PAT_ROWNUM.is_match(&query.raw) && !query.raw_upper().contains("ORDER BY") {
            return vec![self.build_issue(
                query,
                "ROWNUM used without ORDER BY - non-deterministic.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct SelectFromDualRule;
static PAT_DUAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bFROM\s+DUAL\b").unwrap());
impl Rule for SelectFromDualRule {
    fn id(&self) -> &'static str {
        "QUAL-ORA-002"
    }
    fn name(&self) -> &'static str {
        "SELECT FROM DUAL in Application SQL"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "FROM DUAL is Oracle-specific legacy syntax."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_DUAL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "SELECT FROM DUAL detected - consider modern syntax.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct OracleNvlInWhereRule;
static PAT_NVL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b.*\bNVL\s*\(").unwrap());
impl Rule for OracleNvlInWhereRule {
    fn id(&self) -> &'static str {
        "QUAL-ORA-003"
    }
    fn name(&self) -> &'static str {
        "NVL in WHERE Clause"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["oracle"])
    }
    fn impact(&self) -> &'static str {
        "NVL() in WHERE makes the predicate non-SARGable."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_NVL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "NVL() in WHERE clause - prevents index usage.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct SqlCalcFoundRowsRule;
static PAT_CALC: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSQL_CALC_FOUND_ROWS\b").unwrap());
impl Rule for SqlCalcFoundRowsRule {
    fn id(&self) -> &'static str {
        "QUAL-MYSQL-001"
    }
    fn name(&self) -> &'static str {
        "Deprecated SQL_CALC_FOUND_ROWS"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "SQL_CALC_FOUND_ROWS disables LIMIT optimisations."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_CALC
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(query, "Deprecated SQL_CALC_FOUND_ROWS usage.", m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct StraightJoinHintRule;
static PAT_STRAIGHT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSTRAIGHT_JOIN\b").unwrap());
impl Rule for StraightJoinHintRule {
    fn id(&self) -> &'static str {
        "QUAL-MYSQL-002"
    }
    fn name(&self) -> &'static str {
        "STRAIGHT_JOIN Hint"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "Forced join order may become suboptimal."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_STRAIGHT
            .find(&query.raw)
            .map(|m| vec![self.build_issue(query, "STRAIGHT_JOIN hint detected.", m.as_str())])
            .unwrap_or_default()
    }
}

struct MysqlLockInShareModeRule;
static PAT_LOCK_SHARE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bLOCK\s+IN\s+SHARE\s+MODE\b").unwrap());
impl Rule for MysqlLockInShareModeRule {
    fn id(&self) -> &'static str {
        "QUAL-MYSQL-003"
    }
    fn name(&self) -> &'static str {
        "Deprecated LOCK IN SHARE MODE"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["mysql"])
    }
    fn impact(&self) -> &'static str {
        "LOCK IN SHARE MODE will break in future MySQL versions."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_LOCK_SHARE
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Deprecated LOCK IN SHARE MODE - use FOR SHARE.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct AnsiNullsOffRule;
static PAT_ANSI: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSET\s+ANSI_NULLS\s+OFF\b").unwrap());
impl Rule for AnsiNullsOffRule {
    fn id(&self) -> &'static str {
        "QUAL-TSQL-001"
    }
    fn name(&self) -> &'static str {
        "SET ANSI_NULLS OFF"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "Code relying on ANSI_NULLS OFF will break when removed."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_ANSI
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "SET ANSI_NULLS OFF detected - deprecated non-standard behavior.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct TsqlQuotedIdentifierOffRule;
static PAT_QUOTED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bSET\s+QUOTED_IDENTIFIER\s+OFF\b").unwrap());
impl Rule for TsqlQuotedIdentifierOffRule {
    fn id(&self) -> &'static str {
        "QUAL-TSQL-002"
    }
    fn name(&self) -> &'static str {
        "SET QUOTED_IDENTIFIER OFF"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "QUOTED_IDENTIFIER OFF breaks indexed views and computed columns."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_QUOTED
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "SET QUOTED_IDENTIFIER OFF - deprecated, breaks indexes.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct PgDoBlockWithoutLanguageRule;
static PAT_DO_BLOCK: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)\bDO\s+\$\$").unwrap());
impl Rule for PgDoBlockWithoutLanguageRule {
    fn id(&self) -> &'static str {
        "QUAL-PG-001"
    }
    fn name(&self) -> &'static str {
        "DO Block Without LANGUAGE"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["postgresql"])
    }
    fn impact(&self) -> &'static str {
        "Implicit language defaults reduce code clarity."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if PAT_DO_BLOCK.is_match(&query.raw) && !query.raw_upper().contains("LANGUAGE") {
            return vec![self.build_issue(
                query,
                "DO block without LANGUAGE specification.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct RedshiftDiststyleAllRule;
static PAT_DIST_ALL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bDISTSTYLE\s+ALL\b").unwrap());
impl Rule for RedshiftDiststyleAllRule {
    fn id(&self) -> &'static str {
        "QUAL-RS-001"
    }
    fn name(&self) -> &'static str {
        "DISTSTYLE ALL on Large Table"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualSchemaDesign)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["redshift"])
    }
    fn impact(&self) -> &'static str {
        "Entire table copied to every node. Only for small dimension tables."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_DIST_ALL
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "DISTSTYLE ALL detected - entire table copied to every node.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct ClickHouseOrderByWithoutLimitRule;
impl Rule for ClickHouseOrderByWithoutLimitRule {
    fn id(&self) -> &'static str {
        "QUAL-CH-001"
    }
    fn name(&self) -> &'static str {
        "ORDER BY Without LIMIT on ClickHouse"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["clickhouse"])
    }
    fn impact(&self) -> &'static str {
        "All data gathered to one node for global sorting."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if !query.is_select() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        if upper.contains("ORDER BY") && !upper.contains("LIMIT") {
            return vec![self.build_issue(
                query,
                "ORDER BY without LIMIT on ClickHouse - full sort on single node.",
                query.snippet(80),
            )];
        }
        Vec::new()
    }
}

struct SnowflakeFlattenWithoutPathRule;
static PAT_FLAT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bFLATTEN\s*\(").unwrap());
impl Rule for SnowflakeFlattenWithoutPathRule {
    fn id(&self) -> &'static str {
        "QUAL-SF-001"
    }
    fn name(&self) -> &'static str {
        "FLATTEN Without Explicit Path"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualReadability)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["snowflake"])
    }
    fn impact(&self) -> &'static str {
        "Without explicit path, FLATTEN depends on column position."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        if let Some(m) = PAT_FLAT.find(&query.raw) {
            let lower = query.raw_lower();
            if !lower.contains("input") && !lower.contains("path") {
                return vec![self.build_issue(
                    query,
                    "FLATTEN without explicit input/path - fragile implicit resolution.",
                    m.as_str(),
                )];
            }
        }
        Vec::new()
    }
}

struct DuckDBOldStyleCastRule;
static PAT_DUCK_CAST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:INTEGER|VARCHAR|FLOAT|DOUBLE|BOOLEAN|DATE|TIMESTAMP)\s*\(\s*\w+\s*\)")
        .unwrap()
});
impl Rule for DuckDBOldStyleCastRule {
    fn id(&self) -> &'static str {
        "QUAL-DUCK-001"
    }
    fn name(&self) -> &'static str {
        "Deprecated Old-Style Type Cast"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Quality
    }
    fn category(&self) -> Option<Category> {
        Some(Category::QualModern)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["duckdb"])
    }
    fn impact(&self) -> &'static str {
        "Old-style casts are visually ambiguous with function calls."
    }
    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_DUCK_CAST
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "Old-style type cast detected - use CAST or :: syntax.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SelectWithoutFromRule),
        Box::new(WildcardInColumnListRule),
        Box::new(MissingAliasRule),
        Box::new(CommentedCodeRule),
        Box::new(InsertWithoutColumnListRule),
        Box::new(NullComparisonRule),
        Box::new(CaseWithoutElseRule),
        Box::new(ImplicitJoinRule),
        Box::new(HardcodedDateRule),
        Box::new(UnionWithoutAllRule),
        Box::new(DuplicateConditionRule),
        Box::new(ExcessiveCaseNestingRule),
        Box::new(ExcessiveSubqueryNestingRule),
        Box::new(GodQueryRule),
        Box::new(CyclomaticComplexityRule),
        Box::new(LongQueryRule),
        Box::new(InconsistentTableNamingRule),
        Box::new(AmbiguousAliasRule),
        Box::new(HungarianNotationRule),
        Box::new(ReservedWordAsColumnRule),
        Box::new(MissingColumnCommentsRule),
        Box::new(MagicStringWithoutCommentRule),
        Box::new(ComplexLogicWithoutExplanationRule),
        Box::new(MissingPrimaryKeyRule),
        Box::new(MissingForeignKeyRule),
        Box::new(LackOfIndexingOnForeignKeyRule),
        Box::new(UsingFloatForCurrencyRule),
        Box::new(NonDeterministicQueryRule),
        Box::new(OrderByMissingForPaginationRule),
        Box::new(HardcodedTestDataRule),
        Box::new(TodoFixmeCommentRule),
        Box::new(TempTableNotCleanedUpRule),
        Box::new(UnusedObjectRule),
        Box::new(UnreachableCodeRule),
        Box::new(DuplicateQueryRule),
        Box::new(DbtMissingRefRule),
        Box::new(DbtHardcodedSchemaRule),
        Box::new(JsonbOperatorSpacingRule),
        Box::new(RownumWithoutOrderByRule),
        Box::new(SelectFromDualRule),
        Box::new(OracleNvlInWhereRule),
        Box::new(SqlCalcFoundRowsRule),
        Box::new(StraightJoinHintRule),
        Box::new(MysqlLockInShareModeRule),
        Box::new(AnsiNullsOffRule),
        Box::new(TsqlQuotedIdentifierOffRule),
        Box::new(PgDoBlockWithoutLanguageRule),
        Box::new(RedshiftDiststyleAllRule),
        Box::new(ClickHouseOrderByWithoutLimitRule),
        Box::new(SnowflakeFlattenWithoutPathRule),
        Box::new(DuckDBOldStyleCastRule),
    ]
}
