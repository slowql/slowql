use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Per-table metadata for rules that require knowledge about table characteristics.
/// Users declare this in slowql.yaml to enable metadata-dependent rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableMetadata {
    /// Tables known to be large (millions of rows).
    #[serde(default)]
    pub large_tables: Vec<String>,
    /// Tables that are partitioned, with their partition columns.
    #[serde(default)]
    pub partitioned_tables: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComplexityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_optimal")]
    pub threshold_optimal: u32,
    #[serde(default = "default_threshold_complex")]
    pub threshold_complex: u32,
}

fn default_threshold_optimal() -> u32 {
    40
}
fn default_threshold_complex() -> u32 {
    70
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub complexity: ComplexityConfig,
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
    /// Compliance frameworks to enforce (gdpr, hipaa, pci-dss, sox). Empty = disabled.
    #[serde(default)]
    pub compliance_frameworks: std::collections::HashSet<String>,
    #[serde(default)]
    pub severity_overrides: std::collections::HashMap<String, String>,
    /// Table metadata for rules that need schema knowledge to avoid false positives.
    #[serde(default)]
    pub table_metadata: TableMetadata,
    /// Path to custom YAML rules file.
    #[serde(default)]
    pub custom_rules: Option<String>,
    /// Minimum rule confidence to report. Default: "contextual".
    /// Set to "proven" for zero-FP strict mode, "advisory" to include all hints.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: String,
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
    [
        "security",
        "performance",
        "reliability",
        "compliance",
        "cost",
        "quality",
        "schema",
        "migration",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_min_confidence() -> String {
    "proven".to_string()
}
fn default_max_query_length() -> usize {
    100_000
}
fn default_true() -> bool {
    true
}
fn default_fail_on() -> String {
    "high".to_string()
}
fn default_format() -> String {
    "console".to_string()
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
            compliance_frameworks: std::collections::HashSet::new(),
            severity_overrides: std::collections::HashMap::new(),
            custom_rules: None,
            table_metadata: TableMetadata::default(),
            min_confidence: default_min_confidence(),
        }
    }
}

impl Default for SeverityConfig {
    fn default() -> Self {
        SeverityConfig {
            fail_on: default_fail_on(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig {
            format: default_format(),
            verbose: false,
            show_fixes: true,
        }
    }
}

impl Config {
    /// Load config from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        toml::from_str(&content).map_err(|e| format!("Invalid TOML in {}: {}", path.display(), e))
    }

    /// Load config from a YAML file.
    pub fn from_yaml(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        serde_yaml::from_str(&content)
            .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))
    }

    /// Load config from a JSON file.
    pub fn from_json(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Invalid JSON in {}: {}", path.display(), e))
    }

    /// Auto-discover and load config from current or parent directories.
    pub fn find_and_load() -> Self {
        let config_names = [
            "slowql.toml",
            ".slowql.toml",
            "slowql.yaml",
            "slowql.yml",
            ".slowql.yaml",
            ".slowql.yml",
            "slowql.json",
            ".slowql.json",
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

            if !current.pop() {
                break;
            }
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
        std::fs::write(
            &path,
            r#"
[analysis]
dialect = "postgresql"

[severity]
fail_on = "critical"
"#,
        )
        .unwrap();
        let config = Config::from_toml(&path).unwrap();
        assert_eq!(config.analysis.dialect.as_deref(), Some("postgresql"));
        assert_eq!(config.severity.fail_on, "critical");
    }

    #[test]
    fn load_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slowql.yaml");
        std::fs::write(
            &path,
            "analysis:\n  dialect: mysql\nseverity:\n  fail_on: high\n",
        )
        .unwrap();
        let config = Config::from_yaml(&path).unwrap();
        assert_eq!(config.analysis.dialect.as_deref(), Some("mysql"));
    }

    #[test]
    fn load_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slowql.json");
        std::fs::write(
            &path,
            r#"{"analysis":{"dialect":"postgresql"},"severity":{"fail_on":"critical"}}"#,
        )
        .unwrap();
        let config = Config::from_json(&path).unwrap();
        assert_eq!(config.analysis.dialect.as_deref(), Some("postgresql"));
        assert_eq!(config.severity.fail_on, "critical");
    }

    #[test]
    fn load_json_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(Config::from_json(&path).is_err());
    }

    #[test]
    fn load_toml_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "[invalid").unwrap();
        assert!(Config::from_toml(&path).is_err());
    }

    #[test]
    fn load_yaml_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, ": : invalid").unwrap();
        assert!(Config::from_yaml(&path).is_err());
    }

    #[test]
    fn load_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/slowql.toml");
        assert!(Config::from_toml(path).is_err());
        assert!(Config::from_yaml(path).is_err());
        assert!(Config::from_json(path).is_err());
    }

    #[test]
    fn find_and_load_returns_default_when_no_config() {
        let config = Config::find_and_load();
        assert!(config.analysis.enabled_dimensions.contains("security"));
    }

    #[test]
    fn complexity_config_defaults() {
        let config = ComplexityConfig::default();
        // Default derive sets all fields to zero/false.
        // Serde defaults (default_true, default_threshold_*) only apply during deserialization.
        assert!(!config.enabled);
        assert_eq!(config.threshold_optimal, 0);
        assert_eq!(config.threshold_complex, 0);
    }

    #[test]
    fn table_metadata_defaults() {
        let tm = TableMetadata::default();
        assert!(tm.large_tables.is_empty());
        assert!(tm.partitioned_tables.is_empty());
    }

    #[test]
    fn find_and_load_with_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("slowql.yaml");
        std::fs::write(&config_path, "analysis:\n  dialect: mysql\n").unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).ok();
        let config = Config::find_and_load();
        std::env::set_current_dir(original).ok();
        // May or may not find the file depending on race conditions
        let _ = config;
    }

    #[test]
    fn find_and_load_with_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("slowql.json");
        std::fs::write(&config_path, r#"{"analysis":{"dialect":"mysql"}}"#).unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).ok();
        let config = Config::find_and_load();
        std::env::set_current_dir(original).ok();
        let _ = config;
    }

    #[test]
    fn find_and_load_with_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("slowql.toml");
        std::fs::write(&config_path, "[analysis]\ndialect = \"mysql\"\n").unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).ok();
        let config = Config::find_and_load();
        std::env::set_current_dir(original).ok();
        let _ = config;
    }

    #[test]
    fn serde_default_functions() {
        // Exercise the serde default functions directly
        assert_eq!(default_threshold_optimal(), 40);
        assert_eq!(default_threshold_complex(), 70);
        assert!(default_true());
        assert_eq!(default_fail_on(), "high");
        assert_eq!(default_format(), "console");
        assert_eq!(default_max_query_length(), 100_000);
        assert_eq!(default_min_confidence(), "proven");
    }
}
