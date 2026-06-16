use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub dialect: Option<String>,
    #[serde(default = "default_dimensions")]
    pub enabled_dimensions: HashSet<String>,
    #[serde(default)]
    pub disabled_rules: HashSet<String>,
    #[serde(default)]
    pub enabled_rules: Option<HashSet<String>>,
    #[serde(default = "default_max_query_length")]
    pub max_query_length: usize,
    #[serde(default = "default_true")]
    pub parallel: bool,
    #[serde(default)]
    pub max_workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityConfig {
    #[serde(default = "default_fail_on")]
    pub fail_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default = "default_true")]
    pub show_fixes: bool,
}

fn default_dimensions() -> HashSet<String> {
    ["security", "performance", "reliability", "compliance", "cost", "quality", "schema", "migration"]
        .iter().map(|s| s.to_string()).collect()
}
fn default_max_query_length() -> usize { 100_000 }
fn default_true() -> bool { true }
fn default_fail_on() -> String { "high".to_string() }
fn default_format() -> String { "console".to_string() }

impl Default for Config {
    fn default() -> Self {
        Config {
            analysis: AnalysisConfig::default(),
            severity: SeverityConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            dialect: None,
            enabled_dimensions: default_dimensions(),
            disabled_rules: HashSet::new(),
            enabled_rules: None,
            max_query_length: default_max_query_length(),
            parallel: true,
            max_workers: 0,
        }
    }
}

impl Default for SeverityConfig {
    fn default() -> Self { SeverityConfig { fail_on: default_fail_on() } }
}

impl Default for OutputConfig {
    fn default() -> Self { OutputConfig { format: default_format(), verbose: false, show_fixes: true } }
}

impl Config {
    /// Load config from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        toml::from_str(&content).map_err(|e| format!("Invalid TOML in {}: {}", path.display(), e))
    }

    /// Load config from a YAML file.
    pub fn from_yaml(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        serde_yaml::from_str(&content).map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))
    }

    /// Load config from a JSON file.
    pub fn from_json(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON in {}: {}", path.display(), e))
    }

    /// Auto-discover and load config from current or parent directories.
    pub fn find_and_load() -> Self {
        let config_names = [
            "slowql.toml", ".slowql.toml",
            "slowql.yaml", "slowql.yml", ".slowql.yaml", ".slowql.yml",
            "slowql.json", ".slowql.json",
        ];

        let mut current = std::env::current_dir().unwrap_or_default();
        loop {
            for name in &config_names {
                let path = current.join(name);
                if path.exists() {
                    let result = match path.extension().and_then(|e| e.to_str()) {
                        Some("toml") => Self::from_toml(&path),
                        Some("yaml") | Some("yml") => Self::from_yaml(&path),
                        Some("json") => Self::from_json(&path),
                        _ => continue,
                    };
                    match result {
                        Ok(config) => return config,
                        Err(e) => {
                            eprintln!("Warning: failed to load {}: {}", path.display(), e);
                            continue;
                        }
                    }
                }
            }

            // Check pyproject.toml
            let pyproject = current.join("pyproject.toml");
            if pyproject.exists() {
                if let Ok(content) = std::fs::read_to_string(&pyproject) {
                    if let Ok(val) = toml::from_str::<toml::Value>(&content) {
                        if let Some(tool) = val.get("tool") {
                            if let Some(slowql) = tool.get("slowql") {
                                if let Ok(config) = slowql.clone().try_into::<Config>() {
                                    return config;
                                }
                            }
                        }
                    }
                }
            }

            if !current.pop() { break; }
        }

        Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_all_dimensions() {
        let config = Config::default();
        assert!(config.analysis.enabled_dimensions.contains("security"));
        assert!(config.analysis.enabled_dimensions.contains("performance"));
        assert!(config.analysis.enabled_dimensions.contains("reliability"));
    }

    #[test]
    fn load_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slowql.toml");
        std::fs::write(&path, r#"
[analysis]
dialect = "postgresql"

[severity]
fail_on = "critical"
"#).unwrap();
        let config = Config::from_toml(&path).unwrap();
        assert_eq!(config.analysis.dialect.as_deref(), Some("postgresql"));
        assert_eq!(config.severity.fail_on, "critical");
    }

    #[test]
    fn load_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slowql.yaml");
        std::fs::write(&path, "analysis:\n  dialect: mysql\nseverity:\n  fail_on: high\n").unwrap();
        let config = Config::from_yaml(&path).unwrap();
        assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
    }
}
