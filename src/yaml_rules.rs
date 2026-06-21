use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use regex::Regex;
use std::path::Path;

/// A rule loaded from YAML configuration.
pub struct YamlRule {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_severity: Severity,
    pub rule_dimension: Dimension,
    pub pattern: Regex,
    pub message_template: String,
    pub rule_impact: String,
}

impl Rule for YamlRule {
    fn id(&self) -> &'static str {
        // Leak the string to get a static reference. This is safe because
        // YAML rules are loaded once at startup and live for the program lifetime.
        Box::leak(self.rule_id.clone().into_boxed_str())
    }
    fn name(&self) -> &'static str {
        Box::leak(self.rule_name.clone().into_boxed_str())
    }
    fn severity(&self) -> Severity {
        self.rule_severity
    }
    fn dimension(&self) -> Dimension {
        self.rule_dimension
    }
    fn impact(&self) -> &'static str {
        Box::leak(self.rule_impact.clone().into_boxed_str())
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        self.pattern
            .find(&query.raw)
            .map(|m| {
                let msg = self.message_template.replace("{match}", m.as_str());
                vec![self.build_issue(query, &msg, m.as_str())]
            })
            .unwrap_or_default()
    }
}

/// Load custom rules from a YAML file.
pub fn load_yaml_rules(path: &Path) -> Result<Vec<Box<dyn Rule>>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    let data: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;

    let rules_array = data
        .get("rules")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| format!("No 'rules' array in {}", path.display()))?;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();

    for spec in rules_array {
        let id = spec
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("YAML rule missing 'id'")?;
        let name = spec.get("name").and_then(|v| v.as_str()).unwrap_or(id);
        let pattern_str = spec
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("YAML rule '{}' missing 'pattern'", id))?;
        let message = spec
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Pattern matched.");
        let impact = spec.get("impact").and_then(|v| v.as_str()).unwrap_or("");

        let severity = match spec
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
        {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Info,
            _ => Severity::Medium,
        };

        let dimension = match spec
            .get("dimension")
            .and_then(|v| v.as_str())
            .unwrap_or("quality")
        {
            "security" => Dimension::Security,
            "performance" => Dimension::Performance,
            "reliability" => Dimension::Reliability,
            "compliance" => Dimension::Compliance,
            "cost" => Dimension::Cost,
            "quality" => Dimension::Quality,
            _ => Dimension::Quality,
        };

        let pattern = Regex::new(&format!("(?i){}", pattern_str))
            .map_err(|e| format!("Invalid regex in rule '{}': {}", id, e))?;

        rules.push(Box::new(YamlRule {
            rule_id: id.to_string(),
            rule_name: name.to_string(),
            rule_severity: severity,
            rule_dimension: dimension,
            pattern,
            message_template: message.to_string(),
            rule_impact: impact.to_string(),
        }));
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_yaml_rules_from_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: "CUSTOM-001"
    name: "No DROP in production"
    severity: "critical"
    dimension: "reliability"
    pattern: "\\bDROP\\s+TABLE\\b"
    message: "DROP TABLE detected: {match}"
"#,
        )
        .unwrap();

        let rules = load_yaml_rules(&path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id(), "CUSTOM-001");
        assert_eq!(rules[0].severity(), Severity::Critical);

        let query = Query {
            raw: "DROP TABLE users".to_string(),
            normalized: "DROP TABLE users".to_string(),
            dialect: "postgresql".to_string(),
            location: crate::models::Location::new(1, 1),
            ..Default::default()
        };
        let issues = rules[0].check(&query);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("DROP TABLE"));
    }

    #[test]
    fn yaml_rule_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: "CUSTOM-002"
    pattern: "\\bDROP\\b"
    message: "DROP detected"
"#,
        )
        .unwrap();

        let rules = load_yaml_rules(&path).unwrap();
        let query = Query {
            raw: "SELECT 1".to_string(),
            normalized: "SELECT 1".to_string(),
            dialect: "postgresql".to_string(),
            location: crate::models::Location::new(1, 1),
            ..Default::default()
        };
        assert!(rules[0].check(&query).is_empty());
    }
}
