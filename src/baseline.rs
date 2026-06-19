use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use crate::models::result::AnalysisResult;
use crate::models::Issue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: Option<String>,
    pub fingerprint: String,
}

impl BaselineEntry {
    pub fn from_issue(issue: &Issue) -> Self {
        let norm_rule = issue.rule_id.to_uppercase();
        let norm_file = issue.location.file.clone().unwrap_or_default();
        let norm_snippet = issue.snippet.split_whitespace().collect::<Vec<_>>().join(" ");
        let payload = format!("{}|{}|{}", norm_rule, norm_file, norm_snippet);

        // Simple hash using std
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        let fingerprint = format!("{:016x}", hasher.finish());

        BaselineEntry {
            rule_id: issue.rule_id.clone(),
            file: issue.location.file.clone(),
            fingerprint,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub created_at: String,
    pub entry_count: usize,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    pub fn generate(result: &AnalysisResult) -> Self {
        let entries: Vec<BaselineEntry> = result.issues.iter().map(BaselineEntry::from_issue).collect();
        Baseline {
            version: result.version.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            entry_count: entries.len(),
            entries,
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("Failed to write baseline: {}", e))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("Baseline file not found: {}", path.display()));
        }
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).map_err(|e| e.to_string())
    }

    pub fn fingerprints(&self) -> HashSet<String> {
        self.entries.iter().map(|e| e.fingerprint.clone()).collect()
    }

    pub fn filter_new(result: AnalysisResult, baseline: &Baseline) -> (AnalysisResult, usize) {
        let known = baseline.fingerprints();
        let mut new_result = AnalysisResult::new();
        new_result.dialect = result.dialect;
        new_result.queries = result.queries;
        new_result.statistics.parse_time_ms = result.statistics.parse_time_ms;

        let mut suppressed = 0;
        for issue in result.issues {
            let entry = BaselineEntry::from_issue(&issue);
            if known.contains(&entry.fingerprint) {
                suppressed += 1;
            } else {
                new_result.add_issue(issue);
            }
        }

        (new_result, suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Dimension, Issue, Location, Severity};

    #[test]
    fn generate_and_filter() {
        let mut result = AnalysisResult::new();
        result.add_issue(Issue::new("TEST-001", "old issue", Severity::High, Dimension::Security, Location::new(1, 1), "SELECT *"));
        result.add_issue(Issue::new("TEST-002", "new issue", Severity::Medium, Dimension::Performance, Location::new(2, 1), "DELETE FROM t"));

        let baseline = Baseline::generate(&result);
        assert_eq!(baseline.entry_count, 2);

        // Add a new issue
        let mut new_result = AnalysisResult::new();
        new_result.add_issue(Issue::new("TEST-001", "old issue", Severity::High, Dimension::Security, Location::new(1, 1), "SELECT *"));
        new_result.add_issue(Issue::new("TEST-003", "brand new", Severity::Low, Dimension::Quality, Location::new(3, 1), "x"));

        let (filtered, suppressed) = Baseline::filter_new(new_result, &baseline);
        assert_eq!(suppressed, 1);
        assert_eq!(filtered.issues.len(), 1);
        assert_eq!(filtered.issues[0].rule_id, "TEST-003");
    }
}
