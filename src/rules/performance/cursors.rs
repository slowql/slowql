use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{DialectSet, Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

struct CursorDeclarationRule;
static PAT_CURSOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bDECLARE\s+\w+\s+CURSOR\b").unwrap());
impl Rule for CursorDeclarationRule {
    fn id(&self) -> &'static str {
        "PERF-CURSOR-001"
    }
    fn name(&self) -> &'static str {
        "Cursor Declaration"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfCursor)
    }
    fn impact(&self) -> &'static str {
        "Cursors process one row at a time. Typically 10-100x slower than set-based SQL."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CURSOR
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Cursor declaration detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct WhileLoopPatternRule;
static PAT_WHILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bWHILE\s+[\(@].*\bBEGIN\b").unwrap());
impl Rule for WhileLoopPatternRule {
    fn id(&self) -> &'static str {
        "PERF-CURSOR-002"
    }
    fn name(&self) -> &'static str {
        "WHILE Loop Pattern"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfCursor)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "WHILE loops in SQL often indicate procedural thinking applied to a set-based language."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_WHILE
            .find(&query.raw)
            .map(|m| {
                let msg = format!("WHILE loop detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

struct NestedLoopJoinHintRule;
static PAT_LOOP_JOIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(LOOP\s+JOIN|INNER\s+LOOP\s+JOIN|LEFT\s+LOOP\s+JOIN|OPTION\s*\(\s*LOOP\s+JOIN\s*\))").unwrap()
});
impl Rule for NestedLoopJoinHintRule {
    fn id(&self) -> &'static str {
        "PERF-CURSOR-003"
    }
    fn name(&self) -> &'static str {
        "Nested Loop Join Hint"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfCursor)
    }
    fn dialects(&self) -> DialectSet {
        DialectSet::new(&["tsql"])
    }
    fn impact(&self) -> &'static str {
        "Forced nested loop joins perform O(n*m) comparisons."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Advisory
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !self.dialect_matches(query) {
            return Vec::new();
        }
        PAT_LOOP_JOIN
            .find(&query.raw)
            .map(|m| {
                let msg = format!("Nested loop join hint detected: {}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CursorDeclarationRule),
        Box::new(WhileLoopPatternRule),
        Box::new(NestedLoopJoinHintRule),
    ]
}
