use crate::rules::base::Rule;
use crate::rules::{
    compliance, cost, migration, performance, quality, reliability, schema, security,
};

pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        rules.extend(security::all_rules());
        rules.extend(performance::all_rules());
        rules.extend(reliability::all_rules());
        rules.extend(compliance::all_rules());
        rules.extend(cost::all_rules());
        rules.extend(quality::all_rules());
        rules.extend(schema::all_rules());
        rules.extend(migration::all_rules());
        RuleRegistry { rules }
    }

    pub fn add_rules(&mut self, rules: Vec<Box<dyn Rule>>) {
        self.rules.extend(rules);
    }

    pub fn all(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn for_dimension(&self, dimension: &str) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.dimension().as_str() == dimension)
            .map(|r| r.as_ref())
            .collect()
    }

    pub fn enabled_for_dimensions(
        &self,
        enabled: &std::collections::HashSet<String>,
    ) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| enabled.contains(r.dimension().as_str()))
            .map(|r| r.as_ref())
            .collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn default_registry_is_non_empty() {
        let registry = RuleRegistry::default();
        assert!(registry.all().len() > 100);
    }

    #[test]
    fn enabled_for_dimensions_empty_set_returns_nothing() {
        let registry = RuleRegistry::new();
        let enabled = std::collections::HashSet::new();
        let result = registry.enabled_for_dimensions(&enabled);
        assert!(result.is_empty());
    }
}
