use crate::models::issue::Fix;

pub struct AutoFixer;

impl AutoFixer {
    pub fn apply_fix(query: &str, fix: &Fix) -> String {
        let mut updated = query.to_string();

        if let (Some(start), Some(end)) = (fix.start, fix.end) {
            if start <= end
                && end <= query.len()
                && (fix.original.is_empty() || query[start..end] == fix.original)
            {
                updated = format!("{}{}{}", &query[..start], fix.replacement, &query[end..]);
            }
        } else if !fix.original.is_empty() && query.contains(&fix.original) {
            updated = query.replacen(&fix.original, &fix.replacement, 1);
        }

        updated
    }

    pub fn apply_all_fixes(query: &str, fixes: &[Fix]) -> String {
        let mut updated = query.to_string();

        // Span-based fixes first (right to left to preserve offsets)
        let mut span_fixes: Vec<&Fix> = fixes
            .iter()
            .filter(|f| f.start.is_some() && f.end.is_some())
            .collect();
        span_fixes.sort_by_key(|b| std::cmp::Reverse(b.start));

        for fix in &span_fixes {
            updated = Self::apply_fix(&updated, fix);
        }

        // Text-based fixes
        for fix in fixes
            .iter()
            .filter(|f| f.start.is_none() && f.end.is_none())
        {
            if !fix.original.is_empty() && updated.contains(&fix.original) {
                updated = updated.replacen(&fix.original, &fix.replacement, 1);
            }
        }

        updated
    }

    pub fn preview_diff(original: &str, fixes: &[Fix]) -> String {
        let updated = Self::apply_all_fixes(original, fixes);
        if updated == original {
            return String::new();
        }

        let mut diff = String::new();
        diff.push_str("--- original.sql\n");
        diff.push_str("+++ fixed.sql\n");

        for (i, (old_line, new_line)) in original.lines().zip(updated.lines()).enumerate() {
            if old_line != new_line {
                diff.push_str(&format!("@@ -{0},{0} +{0},{0} @@\n", i + 1));
                diff.push_str(&format!("-{}\n", old_line));
                diff.push_str(&format!("+{}\n", new_line));
            }
        }

        diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::issue::FixConfidence;

    #[test]
    fn apply_text_fix() {
        let fix = Fix::safe("fix", "= NULL", "IS NULL", "TEST");
        let result = AutoFixer::apply_fix("SELECT * FROM t WHERE x = NULL", &fix);
        assert!(result.contains("IS NULL"));
        assert!(!result.contains("= NULL"));
    }

    #[test]
    fn apply_span_fix() {
        let fix = Fix {
            description: "fix".to_string(),
            original: "END".to_string(),
            replacement: "ELSE NULL END".to_string(),
            is_safe: true,
            confidence: FixConfidence::Safe,
            rule_id: "TEST".to_string(),
            start: Some(42),
            end: Some(45),
        };
        let sql = "SELECT CASE WHEN status = 1 THEN 'active' END FROM users";
        let result = AutoFixer::apply_fix(sql, &fix);
        assert!(result.contains("ELSE NULL END"));
    }

    #[test]
    fn preview_shows_diff() {
        let fix = Fix::safe("fix", "= NULL", "IS NULL", "TEST");
        let diff = AutoFixer::preview_diff("SELECT * FROM t WHERE x = NULL", &[fix]);
        assert!(diff.contains("IS NULL"));
        assert!(diff.contains("= NULL"));
    }

    #[test]
    fn no_change_returns_empty() {
        let fix = Fix::safe("fix", "NONEXISTENT", "replacement", "TEST");
        let diff = AutoFixer::preview_diff("SELECT 1", &[fix]);
        assert!(diff.is_empty());
    }
}
