use regex::Regex;
use once_cell::sync::Lazy;

static JINJA_BLOCK_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{#.*?#\}").unwrap());
static JINJA_CONTROL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{%.*?%\}").unwrap());
static JINJA_EXPR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{\{.*?\}\}").unwrap());

/// Replace Jinja syntax with safe dummy identifiers,
/// preserving string length so line/column numbers stay accurate.
pub fn strip_jinja(sql: &str) -> String {
    let mut result = sql.to_string();

    // Block comments {# ... #} -> spaces
    result = JINJA_BLOCK_COMMENT.replace_all(&result, |caps: &regex::Captures| {
        " ".repeat(caps[0].len())
    }).to_string();

    // Control blocks {% ... %} -> spaces
    result = JINJA_CONTROL.replace_all(&result, |caps: &regex::Captures| {
        " ".repeat(caps[0].len())
    }).to_string();

    // Expressions {{ ... }} -> __jinja padded with underscores
    result = JINJA_EXPR.replace_all(&result, |caps: &regex::Captures| {
        let len = caps[0].len();
        let prefix = "__jinja";
        if len <= prefix.len() {
            "x".repeat(len)
        } else {
            format!("{}{}", prefix, "_".repeat(len - prefix.len()))
        }
    }).to_string();

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jinja_expressions() {
        let sql = "SELECT * FROM {{ ref('users') }} WHERE id = 1";
        let stripped = strip_jinja(sql);
        assert!(!stripped.contains("{{"));
        assert!(!stripped.contains("}}"));
        assert!(stripped.contains("__jinja"));
        assert_eq!(stripped.len(), sql.len());
    }

    #[test]
    fn strip_jinja_control_blocks() {
        let sql = "{% if condition %}SELECT 1{% endif %}";
        let stripped = strip_jinja(sql);
        assert!(!stripped.contains("{%"));
        assert!(stripped.contains("SELECT 1"));
        assert_eq!(stripped.len(), sql.len());
    }

    #[test]
    fn strip_jinja_comments() {
        let sql = "{# This is a comment #}SELECT 1";
        let stripped = strip_jinja(sql);
        assert!(!stripped.contains("{#"));
        assert!(stripped.contains("SELECT 1"));
        assert_eq!(stripped.len(), sql.len());
    }

    #[test]
    fn preserves_non_jinja() {
        let sql = "SELECT * FROM users WHERE id = 1";
        assert_eq!(strip_jinja(sql), sql);
    }
}
