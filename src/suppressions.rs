use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

static DIRECTIVE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)--\s*slowql[:-]\s*(disable-file|disable-next-line|disable-line|disable|enable)(?:\s+(.+))?$").unwrap()
});

/// Parse a rule list from a directive. Returns None for "all rules".
fn parse_rule_list(raw: Option<&str>) -> Option<HashSet<String>> {
    match raw {
        None | Some("") => None, // all rules
        Some(s) => {
            let rules: HashSet<String> = s
                .split([',', ' '])
                .map(|r| r.trim().to_uppercase())
                .filter(|r| !r.is_empty())
                .collect();
            if rules.is_empty() { None } else { Some(rules) }
        }
    }
}

/// Check if a rule ID matches a set of suppression patterns (exact or prefix).
fn matches_rules(rule_id: &str, rules: &Option<HashSet<String>>) -> bool {
    match rules {
        None => true, // all rules suppressed
        Some(set) => {
            let upper = rule_id.to_uppercase();
            set.iter().any(|pattern| upper == *pattern || upper.starts_with(&format!("{}-", pattern)))
        }
    }
}

pub struct SuppressionMap {
    /// Line-level suppressions: line -> rule set (None = all)
    line_rules: HashMap<u32, Option<HashSet<String>>>,
    /// File-level suppressions (None = all, Some = specific rules)
    file_rules: Option<Option<HashSet<String>>>,
    /// Active block suppressions: (start_line, rule set)
    block_ranges: Vec<(u32, u32, Option<HashSet<String>>)>,
}

impl SuppressionMap {
    pub fn is_suppressed(&self, line: u32, rule_id: &str) -> bool {
        // 1. File-level
        if let Some(ref rules) = self.file_rules {
            if matches_rules(rule_id, rules) {
                return true;
            }
        }

        // 2. Line-level (exact line only)
        if let Some(rules) = self.line_rules.get(&line) {
            if matches_rules(rule_id, rules) {
                return true;
            }
        }

        // 3. Block ranges
        for &(start, end, ref rules) in &self.block_ranges {
            if line >= start && line <= end && matches_rules(rule_id, rules) {
                return true;
            }
        }

        false
    }
}

/// Parse all suppression directives from SQL source.
pub fn parse_suppressions(sql: &str) -> SuppressionMap {
    let mut line_rules: HashMap<u32, Option<HashSet<String>>> = HashMap::new();
    let mut file_rules: Option<Option<HashSet<String>>> = None;
    let mut block_ranges: Vec<(u32, u32, Option<HashSet<String>>)> = Vec::new();

    // Track open blocks: (start_line, rules)
    let mut open_blocks: Vec<(u32, Option<HashSet<String>>)> = Vec::new();

    let lines: Vec<&str> = sql.lines().collect();
    let total_lines = lines.len() as u32;

    for (idx, line_text) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;

        if let Some(caps) = DIRECTIVE_RE.captures(line_text) {
            let directive = caps.get(1).unwrap().as_str().to_lowercase();
            let rules = parse_rule_list(caps.get(2).map(|m| m.as_str()));

            match directive.as_str() {
                "disable-file" => {
                    file_rules = Some(rules);
                }
                "disable-line" => {
                    line_rules.insert(line_num, rules);
                }
                "disable-next-line" => {
                    // Find next non-blank, non-comment line
                    let mut target = line_num + 1;
                    for k in (idx + 1)..lines.len() {
                        let trimmed = lines[k].trim();
                        if !trimmed.is_empty() && !trimmed.starts_with("--") {
                            target = (k + 1) as u32;
                            break;
                        }
                    }
                    line_rules.insert(target, rules);
                }
                "disable" => {
                    open_blocks.push((line_num, rules));
                }
                "enable" => {
                    // Close the most recent matching block
                    if let Some((start, block_rules)) = open_blocks.pop() {
                        block_ranges.push((start, line_num, block_rules));
                    }
                }
                _ => {}
            }
        }
    }

    // Close any unclosed blocks at EOF
    for (start, block_rules) in open_blocks {
        block_ranges.push((start, total_lines + 1, block_rules));
    }

    SuppressionMap {
        line_rules,
        file_rules,
        block_ranges,
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
    fn disable_next_line_specific() {
        let sql = "-- slowql-disable-next-line PERF-SCAN-001\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn disable_next_line_all() {
        let sql = "-- slowql-disable-next-line\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn disable_line() {
        let sql = "SELECT * FROM users -- slowql-disable-line PERF-SCAN-001";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(1, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(1, "SEC-INJ-001"));
    }

    #[test]
    fn disable_file() {
        let sql = "-- slowql-disable-file PERF-SCAN-001\nSELECT * FROM users;\nSELECT * FROM orders;";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(3, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn disable_file_all() {
        let sql = "-- slowql-disable-file\nSELECT * FROM users;";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn block_disable_enable() {
        let sql = "SELECT 1;\n-- slowql-disable PERF-SCAN-001\nSELECT * FROM users;\nSELECT * FROM orders;\n-- slowql-enable\nSELECT * FROM t;";
        let map = parse_suppressions(sql);
        assert!(!map.is_suppressed(1, "PERF-SCAN-001"));
        assert!(map.is_suppressed(3, "PERF-SCAN-001"));
        assert!(map.is_suppressed(4, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(6, "PERF-SCAN-001"));
    }

    #[test]
    fn block_unclosed_extends_to_eof() {
        let sql = "-- slowql-disable SEC-INJ\nSELECT 1;\nSELECT 2;";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
        assert!(map.is_suppressed(3, "SEC-INJ-001"));
        assert!(!map.is_suppressed(2, "PERF-SCAN-001"));
    }

    #[test]
    fn prefix_matching() {
        let sql = "-- slowql-disable-next-line PERF\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "PERF-IDX-002"));
        assert!(!map.is_suppressed(2, "SEC-INJ-001"));
    }

    #[test]
    fn multiple_rules_comma_separated() {
        let sql = "-- slowql-disable-next-line PERF-SCAN-001, SEC-INJ-001\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(map.is_suppressed(2, "SEC-INJ-001"));
        assert!(!map.is_suppressed(2, "REL-DATA-001"));
    }

    #[test]
    fn suppression_does_not_leak() {
        let sql = "-- slowql-disable-next-line PERF-SCAN-001\nSELECT * FROM users;\nSELECT * FROM orders";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
        assert!(!map.is_suppressed(3, "PERF-SCAN-001"));
    }

    #[test]
    fn backward_compat_colon_syntax() {
        let sql = "-- slowql: disable PERF-SCAN-001\nSELECT * FROM users";
        let map = parse_suppressions(sql);
        assert!(map.is_suppressed(2, "PERF-SCAN-001"));
    }
}
