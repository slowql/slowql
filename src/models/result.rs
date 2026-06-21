use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::models::issue::Issue;
use crate::models::query::Query;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Statistics {
    pub total_queries: usize,
    pub total_issues: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_dimension: HashMap<String, usize>,
    pub analysis_time_ms: f64,
    pub parse_time_ms: f64,
    pub max_complexity: u32,
    pub avg_complexity: f64,
}

impl Statistics {
    pub fn new() -> Self {
        let mut by_severity = HashMap::new();
        for sev in ["critical", "high", "medium", "low", "info"] {
            by_severity.insert(sev.to_string(), 0);
        }
        let mut by_dimension = HashMap::new();
        for dim in [
            "security",
            "performance",
            "reliability",
            "compliance",
            "cost",
            "quality",
            "schema",
            "data",
            "migration",
            "operational",
            "business",
        ] {
            by_dimension.insert(dim.to_string(), 0);
        }
        Statistics {
            by_severity,
            by_dimension,
            ..Default::default()
        }
    }

    pub fn record_issue(&mut self, issue: &Issue) {
        self.total_issues += 1;
        *self
            .by_severity
            .entry(issue.severity.as_str().to_string())
            .or_insert(0) += 1;
        *self
            .by_dimension
            .entry(issue.dimension.as_str().to_string())
            .or_insert(0) += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub issues: Vec<Issue>,
    pub statistics: Statistics,
    pub dialect: Option<String>,
    pub queries: Vec<Query>,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub suppressed_count: usize,
}

impl AnalysisResult {
    pub fn new() -> Self {
        AnalysisResult {
            issues: Vec::new(),
            statistics: Statistics::new(),
            dialect: None,
            queries: Vec::new(),
            timestamp: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            suppressed_count: 0,
        }
    }

    pub fn add_issue(&mut self, issue: Issue) {
        self.statistics.record_issue(&issue);
        self.issues.push(issue);
    }

    pub fn has_critical(&self) -> bool {
        self.statistics
            .by_severity
            .get("critical")
            .copied()
            .unwrap_or(0)
            > 0
    }

    pub fn has_high(&self) -> bool {
        self.statistics
            .by_severity
            .get("high")
            .copied()
            .unwrap_or(0)
            > 0
    }

    pub fn exit_code(&self) -> i32 {
        if self.has_critical() {
            return 3;
        }
        if self.has_high() {
            return 2;
        }
        let info_count = self
            .statistics
            .by_severity
            .get("info")
            .copied()
            .unwrap_or(0);
        if self.statistics.total_issues > info_count {
            return 1;
        }
        0
    }

    pub fn sorted_by_severity(&self) -> Vec<&Issue> {
        let mut issues: Vec<&Issue> = self.issues.iter().collect();
        issues.sort_by(|a, b| b.severity.cmp(&a.severity));
        issues
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}
