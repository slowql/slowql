use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct ExtractedQuery {
    pub raw: String,
    pub line: u32,
    pub column: u32,
    pub file_path: String,
    pub is_dynamic: bool,
    pub language: String,
}

static SQL_START: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WITH|TRUNCATE|GRANT|REVOKE)\b").unwrap()
});

pub fn extract_from_source(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let ext = file_path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "py" => extract_python(content, file_path),
        "ts" | "js" | "tsx" | "jsx" => extract_generic(content, file_path, "typescript"),
        "java" | "kt" => extract_generic(content, file_path, "java"),
        "go" => extract_generic(content, file_path, "go"),
        "rb" => extract_generic(content, file_path, "ruby"),
        "cs" => extract_generic(content, file_path, "csharp"),
        _ => Vec::new(),
    }
}

fn overlaps(used: &[(usize, usize)], start: usize, end: usize) -> bool {
    used.iter().any(|&(s, e)| start < e && end > s)
}

fn offset_to_line_col(content: &str, offset: usize) -> (u32, u32) {
    let prefix = &content[..offset.min(content.len())];
    let line = prefix.matches('\n').count() as u32 + 1;
    let last_nl = prefix.rfind('\n').map(|p| p + 1).unwrap_or(0);
    let col = (offset - last_nl + 1) as u32;
    (line, col)
}

fn strip_python_quote_wrapper(raw: &str) -> String {
    if raw.starts_with("\"\"\"") && raw.ends_with("\"\"\"") && raw.len() >= 6 {
        return raw[3..raw.len() - 3].to_string();
    }
    if raw.starts_with("'''") && raw.ends_with("'''") && raw.len() >= 6 {
        return raw[3..raw.len() - 3].to_string();
    }
    if raw.starts_with('f') && raw.len() >= 3 {
        let inner = &raw[1..];
        return strip_python_quote_wrapper(inner);
    }
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        return raw[1..raw.len() - 1].to_string();
    }
    if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

fn extract_python(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let mut queries = Vec::new();
    let mut used_ranges: Vec<(usize, usize)> = Vec::new();

    static PY_TRIPLE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?s)(""".*?"""|'''.*?''')"#).unwrap()
    });

    static PY_FSTRING: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?m)\bf("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#).unwrap()
    });

    static PY_SINGLE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?m)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#).unwrap()
    });

    for m in PY_TRIPLE.find_iter(content) {
        let inner = strip_python_quote_wrapper(m.as_str());
        if SQL_START.is_match(inner.trim()) {
            let (line, col) = offset_to_line_col(content, m.start());
            queries.push(ExtractedQuery {
                raw: inner.trim().to_string(),
                line,
                column: col,
                file_path: file_path.to_string(),
                is_dynamic: false,
                language: "python".to_string(),
            });
        }
        used_ranges.push((m.start(), m.end()));
    }

    for caps in PY_FSTRING.captures_iter(content) {
        let m = caps.get(0).unwrap();
        if overlaps(&used_ranges, m.start(), m.end()) {
            continue;
        }
        let inner = strip_python_quote_wrapper(m.as_str());
        if SQL_START.is_match(inner.trim()) {
            let (line, col) = offset_to_line_col(content, m.start());
            queries.push(ExtractedQuery {
                raw: inner.trim().to_string(),
                line,
                column: col,
                file_path: file_path.to_string(),
                is_dynamic: true,
                language: "python".to_string(),
            });
        }
        used_ranges.push((m.start(), m.end()));
    }

    for m in PY_SINGLE.find_iter(content) {
        if overlaps(&used_ranges, m.start(), m.end()) {
            continue;
        }
        let inner = strip_python_quote_wrapper(m.as_str());
        if SQL_START.is_match(inner.trim()) {
            let (line, col) = offset_to_line_col(content, m.start());
            queries.push(ExtractedQuery {
                raw: inner.trim().to_string(),
                line,
                column: col,
                file_path: file_path.to_string(),
                is_dynamic: false,
                language: "python".to_string(),
            });
        }
    }

    queries
}

fn extract_generic(content: &str, file_path: &str, language: &str) -> Vec<ExtractedQuery> {
    let mut queries = Vec::new();

    static STRING_PAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)"#).unwrap()
    });

    for m in STRING_PAT.find_iter(content) {
        let raw_match = m.as_str();
        if raw_match.len() < 2 {
            continue;
        }
        let inner = &raw_match[1..raw_match.len() - 1];

        if SQL_START.is_match(inner.trim()) {
            let (line, col) = offset_to_line_col(content, m.start());

            let is_dynamic = match language {
                "typescript" | "ruby" => inner.contains("${") || inner.contains("#{"),
                "go" => inner.contains("%v") || inner.contains("%s") || inner.contains("%d"),
                _ => false,
            };

            queries.push(ExtractedQuery {
                raw: inner.trim().to_string(),
                line,
                column: col,
                file_path: file_path.to_string(),
                is_dynamic,
                language: language.to_string(),
            });
        }
    }

    queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_python_triple_quoted() {
        let code = r#"
query = """
SELECT * FROM users WHERE id = 1
"""
"#;
        let extracted = extract_from_source(code, "app.py");
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].raw.contains("SELECT * FROM users"));
        assert!(!extracted[0].is_dynamic);
    }

    #[test]
    fn extract_python_single_quoted() {
        let code = r#"db.execute("SELECT id FROM users WHERE email = ?", (email,))"#;
        let extracted = extract_from_source(code, "app.py");
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].raw.contains("SELECT id FROM users"));
    }

    #[test]
    fn extract_python_fstring_is_dynamic() {
        let code = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let extracted = extract_from_source(code, "app.py");
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].is_dynamic);
    }

    #[test]
    fn extract_typescript() {
        let code = r#"const sql = "SELECT * FROM orders WHERE user_id = ?";"#;
        let extracted = extract_from_source(code, "app.ts");
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].raw.contains("SELECT * FROM orders"));
    }

    #[test]
    fn extract_java() {
        let code = r#"String sql = "DELETE FROM sessions WHERE expired = true";"#;
        let extracted = extract_from_source(code, "App.java");
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn extract_go() {
        let code = r#"query := "INSERT INTO users (name) VALUES (?)""#;
        let extracted = extract_from_source(code, "main.go");
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn extract_ruby() {
        let code = r#"sql = "UPDATE users SET active = true WHERE id = #{id}""#;
        let extracted = extract_from_source(code, "app.rb");
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].is_dynamic);
    }

    #[test]
    fn non_sql_strings_ignored() {
        let code = r#"msg = "Hello world"; name = "John""#;
        let extracted = extract_from_source(code, "app.py");
        assert_eq!(extracted.len(), 0);
    }
}
