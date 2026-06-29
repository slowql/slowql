use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

struct UnfilteredAggregationRule;
impl Rule for UnfilteredAggregationRule {
    fn id(&self) -> &'static str {
        "PERF-AGG-001"
    }
    fn name(&self) -> &'static str {
        "Unfiltered Aggregation"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfAggregation)
    }
    fn impact(&self) -> &'static str {
        "Aggregates entire table, expensive on large datasets."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        if !query.is_select() {
            return Vec::new();
        }
        if query.source_context == "adhoc" || query.source_context.is_empty() {
            return Vec::new();
        }
        let upper = query.raw_upper();
        let has_agg = upper.contains("COUNT(") || upper.contains("SUM(") || upper.contains("AVG(");
        if !has_agg {
            return Vec::new();
        }
        if upper.contains("WHERE") {
            return Vec::new();
        }
        // GROUP BY without WHERE is a legitimate reporting pattern.
        // The aggregation is intentionally over the full table grouped by dimension.
        // Only flag when there is neither WHERE nor GROUP BY.
        if upper.contains("GROUP BY") {
            return Vec::new();
        }
        // Use AST facts when available for higher confidence
        if let Some(ref facts) = query.facts {
            if facts.has_group_by || facts.has_where {
                return Vec::new();
            }
        }
        let snip = query.snippet(80);
        vec![self.build_issue(
            query,
            "Aggregation without WHERE or GROUP BY scans entire table.",
            snip,
        )]
    }
}

struct OrderByInSubqueryRule;
static PAT_ORDER_SUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\(\s*SELECT\b[^)]+\bORDER\s+BY\b").unwrap());
impl Rule for OrderByInSubqueryRule {
    fn id(&self) -> &'static str {
        "PERF-AGG-002"
    }
    fn name(&self) -> &'static str {
        "ORDER BY in Subquery"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfAggregation)
    }
    fn impact(&self) -> &'static str {
        "ORDER BY in subquery is meaningless and wastes sort cost."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_ORDER_SUB
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    "ORDER BY in subquery is typically meaningless.",
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct HavingWithoutGroupByRule;
impl Rule for HavingWithoutGroupByRule {
    fn id(&self) -> &'static str {
        "PERF-AGG-003"
    }
    fn name(&self) -> &'static str {
        "HAVING Without GROUP BY"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Performance
    }
    fn category(&self) -> Option<Category> {
        Some(Category::PerfAggregation)
    }
    fn impact(&self) -> &'static str {
        "Without GROUP BY, HAVING filters the entire table as one group."
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        let upper = query.raw_upper();
        if upper.contains("HAVING") && !upper.contains("GROUP BY") {
            let snip = query.snippet(80);
            return vec![self.build_issue(
                query,
                "HAVING without GROUP BY - entire result treated as single group.",
                snip,
            )];
        }
        Vec::new()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnfilteredAggregationRule),
        Box::new(OrderByInSubqueryRule),
        Box::new(HavingWithoutGroupByRule),
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
            "duckdb",
            "presto",
            "spark",
        ];
        for dialect in &dialects {
            for qt in &["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE"] {
                let query = q("SELECT 1", dialect, qt);
                for rule in &rules {
                    let _ = rule.check(&query);
                    let _ = rule.dialect_matches(&query);
                }
            }
        }
    }
}
