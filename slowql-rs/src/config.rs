use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub analysis: AnalysisConfig,
    pub severity: SeverityConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub dialect: Option<String>,
    pub enabled_dimensions: HashSet<String>,
    pub disabled_rules: HashSet<String>,
    pub enabled_rules: Option<HashSet<String>>,
    pub max_query_length: usize,
    pub parallel: bool,
    pub max_workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityConfig {
    pub fail_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub verbose: bool,
    pub show_fixes: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            analysis: AnalysisConfig {
                dialect: None,
                enabled_dimensions: [
                    "security", "performance", "reliability", "schema", "migration",
                    "compliance", "cost", "quality",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                disabled_rules: HashSet::new(),
                enabled_rules: None,
                max_query_length: 100_000,
                parallel: true,
                max_workers: 0,
            },
            severity: SeverityConfig {
                fail_on: "high".to_string(),
            },
            output: OutputConfig {
                format: "console".to_string(),
                verbose: false,
                show_fixes: true,
            },
        }
    }
}
