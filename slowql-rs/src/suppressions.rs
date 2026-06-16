use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};

static SUPPRESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)--\s*slowql:\s*disable(?:\s+(.+))?$").unwrap()
});

/// Map of line numbers to suppressed rule IDs.
/// If a line maps to an empty set, all rules are suppressed on that line.
pub struct SuppressionMap {
    /// Line -> set of suppressed rule IDs (empty = all suppressed)
    line_suppressions: HashMap<u32, Option<HashSet<String>>>,
    /// Global file-level suppressions (from line 1 directives without enable)
    file_suppressions: Option<HashSet<String>>,
}

impl SuppressionMap {
    pub fn is_suppressed(&self, line: u32, rule_id: &str) -> bool {
        // Check file-level suppressions
        if let Some(ref file_rules) = self.file_suppressions {
            if file_rules.is_empty() || file_rules.contains(rule_id) {
                return true;
            }
        }

        // Check line-level: the suppression comment on line N suppresses issues on line N+1
        // Also check the same line (inline comment after SQL)
        for check_line in [line, line.saturating_sub(1)] {
            if let Some(suppressed) = self.line_suppressions.get(&check_line) {
                match suppressed {
                    None => return true, // all rules suppressed
                    Some(rules) => {
                        if rules.is_empty() || rules.contains(rule_id) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Parse suppression directives from SQL source.
pub fn parse_suppressions(sql: &str) -> SuppressionMap {
    let mut line_suppressions: HashMap<u32, Option<HashSet<String>>> = HashMap::new();

    for (line_idx, line) in sql.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;

        if let Some(caps) = SUPPRESS_RE.captures(line) {
            let rules = caps.get(1).map(|m| {
                m.as_str()
                    .split([',', ' '])
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<HashSet<String>>()
            });

            match rules {
                Some(r) if !r.is_empty() => {
                    line_suppressions.insert(line_num, Some(r));
                }
                _ => {
                    line_suppressions.insert(line_num, None); // suppress all
                }
            }
        }
    }

    SuppressionMap {
        line_suppressions,
        file_suppressions: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_suppressions() {
        let map = parse_suppressions("SELECT * FROM users");
        assert!(!map.is_suppressed(1, "PERF-SCAN-001"));
    }

    #[test]
    fn suppress_specific_rule() {
        let sql = "-- slowql: disable PERF-SCAN-001\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn suppress_all_rules() {
        let sql = "-- slowql: disable\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn suppress_multiple_rules() {
        let sql = "-- slowql: disable PERF-SCAN-001, SEC-INJ-001\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
        assert!(!map.is_suppressed(2, "REL-DATA-001"));
    }

    #[test]
    fn suppression_does_not_leak() {
        let sql = "-- slowql: disable PERF-SCAN-001\nSELECT * FROM users;\nSELECT * FROM orders";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(3, "PERF-SCAN-001"));
    }
}
