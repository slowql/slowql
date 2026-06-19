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
    Regex::new(r"(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE)\b").unwrap()
});

fn has_sql_structure(upper: &str) -> bool {
    let padded = format!(" {} ", upper);

    padded.contains(" FROM ")
        || padded.contains(" INTO ")
        || padded.contains(" VALUES ")
        || padded.contains(" VALUES(")
        || padded.contains(" WHERE ")
        || padded.contains(" INNER JOIN ")
        || padded.contains(" LEFT JOIN ")
        || padded.contains(" RIGHT JOIN ")
        || padded.contains(" CROSS JOIN ")
        || padded.contains(" FULL JOIN ")
        || padded.contains(" FULL OUTER JOIN ")
        || padded.contains(" JOIN ")
        || padded.contains(" PRIMARY KEY ")
        || padded.contains(" FOREIGN KEY ")
        || padded.contains(" REFERENCES ")
        || padded.contains(" GROUP BY ")
        || padded.contains(" ORDER BY ")
        || padded.contains(" LIMIT ")
        || padded.contains(" OFFSET ")
        || padded.contains(" HAVING ")
        || padded.contains(" UNION SELECT ")
        || padded.contains(" UNION ALL SELECT ")
        || padded.contains(" BETWEEN ")
        || padded.contains(" LIKE ")
        || padded.contains(" IN (")
        || padded.contains(" IDENTIFIED BY ")
        || padded.contains(" SET ")
}

fn ddl_like(upper: &str) -> bool {
    let tokens: Vec<&str> = upper.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }

    match tokens[0] {
        "DROP" | "ALTER" | "TRUNCATE" | "GRANT" | "REVOKE" => {
            if tokens.len() < 2 {
                return false;
            }
            let mut i = 1;
            while i < tokens.len() && matches!(tokens[i], "OR" | "REPLACE" | "TEMP" | "TEMPORARY" | "IF" | "NOT" | "EXISTS") {
                i += 1;
            }
            if i >= tokens.len() {
                return false;
            }
            matches!(
                tokens[i],
                "TABLE" | "INDEX" | "VIEW" | "SEQUENCE" | "SCHEMA" | "DATABASE"
                    | "COLUMN" | "CONSTRAINT" | "TRIGGER" | "FUNCTION"
                    | "PROCEDURE" | "TYPE" | "ROLE" | "USER" | "EXTENSION"
                    | "MATERIALIZED"
            )
        }
        "CREATE" => {
            // Handle both normal SQL and interpolated builder strings like:
            // CREATE#{...} TABLE
            (upper.contains(" TABLE")
                || upper.contains(" INDEX")
                || upper.contains(" VIEW")
                || upper.contains(" SEQUENCE")
                || upper.contains(" SCHEMA")
                || upper.contains(" DATABASE")
                || upper.contains(" CONSTRAINT")
                || upper.contains(" TRIGGER")
                || upper.contains(" FUNCTION")
                || upper.contains(" PROCEDURE")
                || upper.contains(" TYPE")
                || upper.contains(" EXTENSION"))
                && tokens.len() >= 2
        }
        _ => false,
    }
}

fn is_likely_sql(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 10 {
        return false;
    }

    if !SQL_START.is_match(trimmed) {
        return false;
    }

    // Single-word labels like "delete", "create", "update" are not SQL.
    if !trimmed.contains(' ') && !trimmed.contains('(') && !trimmed.contains(';') {
        return false;
    }

    // Reject incomplete SQL fragments from string concatenation such as:
    // "delete from " + table + " where ..."
    // "select " + cols + " from ..."
    let upper_fragment = trimmed.to_uppercase();
    let incomplete_fragments = [
        "DELETE FROM",
        "SELECT",
        "INSERT INTO",
        "UPDATE",
        "WHERE",
        "JOIN",
        "LEFT JOIN",
        "RIGHT JOIN",
        "INNER JOIN",
        "FROM",
        "ORDER BY",
        "GROUP BY",
        "HAVING",
        "VALUES",
        "SET",
    ];
    if incomplete_fragments.iter().any(|frag| upper_fragment == *frag) {
        return false;
    }

    // Reject template fragments and route strings.
    if trimmed.contains("<%")
        || trimmed.contains("%>")
        || trimmed.contains("{%")
        || trimmed.contains("{{")
        || trimmed.contains("(.:format)")
        || trimmed.contains("/:")
        || trimmed.contains("#destroy")
        || trimmed.contains("#create")
        || trimmed.contains("#update")
        || trimmed.contains("#index")
        || trimmed.contains("#show")
        || trimmed.contains("#edit")
    {
        return false;
    }

    // Reject strings that look like English sentences with SQL-verb starts.
    // Real SQL has structure: "DELETE FROM table WHERE ..."
    // Prose has: "delete feature flag from Vercel"
    // Key difference: prose has multiple lowercase words between verb and FROM.
    {
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() >= 3 {
            let first_upper = words[0].to_uppercase();
            if matches!(first_upper.as_str(), "DELETE" | "UPDATE" | "INSERT" | "SELECT" | "CREATE" | "DROP") {
                // Count how many words before a structural SQL keyword
                let structural = ["FROM", "INTO", "SET", "TABLE", "WHERE", "VALUES", "JOIN",
                    "INDEX", "VIEW", "SCHEMA", "DATABASE", "COLUMN", "CONSTRAINT"];
                let mut found_structural = false;
                let mut words_before_structural = 0;
                for w in &words[1..] {
                    if structural.contains(&w.to_uppercase().as_str()) {
                        found_structural = true;
                        break;
                    }
                    words_before_structural += 1;
                }
                // In real SQL, the structural keyword comes within 1-2 words of the verb:
                // DELETE FROM x, INSERT INTO x, UPDATE x SET, SELECT x FROM
                // In prose, there are 2+ words: "delete feature flag from Vercel"
                if found_structural && words_before_structural >= 2 {
                    return false;
                }
                // Special-case English prose like:
                // "delete events from PostHog"
                // "delete experiment from Vercel"
                // "update pagination state from response"
                // These have SQL verbs and FROM, but are not SQL.
                let lower_words: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
                if lower_words.len() >= 4 {
                    let first = &lower_words[0];
                    if ["delete", "update", "create", "insert", "select"].contains(&first.as_str()) {
                        if let Some(from_idx) = lower_words.iter().position(|w| w == "from") {
                            if from_idx >= 2 {
                                return false;
                            }
                        }
                    }
                }
                // If no structural keyword found at all and no SQL punctuation, reject
                if !found_structural {
                    let has_punct = trimmed.contains('(') || trimmed.contains(')')
                        || trimmed.contains('=') || trimmed.contains(',')
                        || trimmed.contains(';') || trimmed.contains('*')
                        || trimmed.contains('\'');
                    if !has_punct {
                        return false;
                    }
                }
            }
        }
    }

    // Reject strings that look like natural language descriptions:
    // They end with a period and lack SQL structural keywords.
    if trimmed.ends_with('.') || trimmed.ends_with(".)") || trimmed.ends_with('?') {
        let upper_check = trimmed.to_uppercase();
        let has_sql_keywords = upper_check.contains(" FROM ")
            || upper_check.contains(" WHERE ")
            || upper_check.contains(" JOIN ")
            || upper_check.contains(" VALUES")
            || upper_check.contains(" SET ")
            || upper_check.contains(" INTO ");
        if !has_sql_keywords {
            return false;
        }
    }

    // Reject natural language prose: common English function words
    // that never appear in valid SQL.
    let lower = trimmed.to_lowercase();
    if [" the ", " a ", " an ", " this ", " that ",
        " is ", " are ", " was ", " were ", " been ",
        " have ", " has ", " had ", " does ", " did ",
        " will ", " would ", " could ", " should ",
        " may ", " might ", " can ", " must ",
        " your ", " their ", " its ", " which ",
        " because ", " although ", " however ",
        " return ", " returns ", " returned ",
        " informing ", " succeeded ", " failing ",
        " silently ", " optionally ", " whether ",
        " object ", " objects ", " needed ",
    ].iter().any(|m| lower.contains(m)) {
        return false;
    }

    let upper = trimmed.to_uppercase();

    // WITH must be a CTE, not natural language.
    if upper.starts_with("WITH ") && !upper.contains(" AS ") && !upper.contains(" AS(") {
        return false;
    }

    has_sql_structure(&upper) || ddl_like(&upper)
}
pub fn extract_from_source(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let ext = file_path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "py" => extract_python(content, file_path),
        "ts" | "js" | "tsx" | "jsx" => extract_sink_aware(content, file_path, "typescript"),
        "java" | "kt" => extract_sink_aware(content, file_path, "java"),
        "go" => extract_sink_aware(content, file_path, "go"),
        "rb" => extract_ruby(content, file_path),
        "cs" => extract_sink_aware(content, file_path, "csharp"),
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

fn strip_quote(raw: &str) -> String {
    if raw.starts_with("\"\"\"") && raw.ends_with("\"\"\"") && raw.len() >= 6 {
        return raw[3..raw.len() - 3].to_string();
    }
    if raw.starts_with("'''") && raw.ends_with("'''") && raw.len() >= 6 {
        return raw[3..raw.len() - 3].to_string();
    }
    if (raw.starts_with('f') || raw.starts_with('r') || raw.starts_with('b')) && raw.len() >= 3 {
        return strip_quote(&raw[1..]);
    }
    if raw.len() >= 2 {
        let c = raw.chars().next().unwrap();
        if c == '"' || c == '\'' || c == '`' {
            let last = raw.chars().last().unwrap();
            if last == c {
                return raw[1..raw.len() - 1].to_string();
            }
        }
    }
    raw.to_string()
}

fn strip_comments(content: &str, lang: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        let is_comment = match lang {
            "ruby" | "python" => trimmed.starts_with('#'),
            "go" | "java" | "typescript" | "csharp" => {
                trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            }
            _ => false,
        };
        if is_comment {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
fn extract_python(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let mut queries = Vec::new();
    let mut used: Vec<(usize, usize)> = Vec::new();

    static TRIPLE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?s)(""".*?"""|'''.*?''')"#).unwrap()
    });

    static FSTRING: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?m)\bf("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#).unwrap()
    });

    static SINGLE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?m)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#).unwrap()
    });

    for m in TRIPLE.find_iter(content) {
        let inner = strip_quote(m.as_str());
        if is_likely_sql(inner.trim()) {
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
        used.push((m.start(), m.end()));
    }

    for caps in FSTRING.captures_iter(content) {
        let m = caps.get(0).unwrap();
        if overlaps(&used, m.start(), m.end()) {
            continue;
        }
        let inner = strip_quote(m.as_str());
        if is_likely_sql(inner.trim()) {
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
        used.push((m.start(), m.end()));
    }

    for m in SINGLE.find_iter(content) {
        if overlaps(&used, m.start(), m.end()) {
            continue;
        }
        let inner = strip_quote(m.as_str());
        if is_likely_sql(inner.trim()) {
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
fn extract_ruby(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let cleaned = strip_comments(content, "ruby");
    let content = &cleaned;
    static RUBY_SINK: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r#"(?is)(?:^|[.(])(?:lease_connection|connection)?\s*\.?\s*"#,
            r#"(?:execute|exec_query|exec_insert|exec_update|exec_delete|select_all|select_value|select_rows|select_one|find_by_sql)\s*\(\s*"#,
            r#"("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#
        ))
        .unwrap()
    });

    static RUBY_HEREDOC_SINK: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r#"(?is)(?:^|[.(])(?:lease_connection|connection)?\s*\.?\s*"#,
            r#"(?:execute|exec_query|exec_insert|exec_update|exec_delete|select_all|select_value|select_rows|select_one|find_by_sql)\s*\(?\s*"#,
            r#"<<"#,
            r#"[~-]?SQL\s*\n([\s\S]*?)\n\s*SQL"#
        ))
        .unwrap()
    });

    let mut queries = Vec::new();

    for caps in RUBY_SINK.captures_iter(content) {
        if let Some(arg) = caps.get(1) {
            let inner = strip_quote(arg.as_str());
            let sql = inner.trim();
            if is_likely_sql(sql) {
                let (line, col) = offset_to_line_col(content, arg.start());
                queries.push(ExtractedQuery {
                    raw: sql.to_string(),
                    line,
                    column: col,
                    file_path: file_path.to_string(),
                    is_dynamic: inner.contains("#{"),
                    language: "ruby".to_string(),
                });
            }
        }
    }

    for caps in RUBY_HEREDOC_SINK.captures_iter(content) {
        if let Some(body) = caps.get(1) {
            let sql = body.as_str().trim();
            if !sql.is_empty() {
                let (line, col) = offset_to_line_col(content, caps.get(0).unwrap().start());
                queries.push(ExtractedQuery {
                    raw: sql.to_string(),
                    line,
                    column: col,
                    file_path: file_path.to_string(),
                    is_dynamic: sql.contains("#{"),
                    language: "ruby".to_string(),
                });
            }
        }
    }

    queries
}

fn is_jpql(sql: &str) -> bool {
    let upper = sql.to_uppercase();
    for prefix in &["FROM ", "DELETE FROM ", "UPDATE "] {
        if let Some(pos) = upper.find(prefix) {
            let after = sql[pos + prefix.len()..].trim_start();
            let first_word: String = after.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if first_word.len() >= 2 {
                let chars: Vec<char> = first_word.chars().collect();
                if chars[0].is_uppercase() && chars[1].is_lowercase() {
                    return true;
                }
            }
        }
    }
    false
}

fn extract_sink_aware(content: &str, file_path: &str, language: &str) -> Vec<ExtractedQuery> {
    let cleaned = strip_comments(content, language);
    let content = &cleaned;
    static SINK_PAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r#"(?is)(?:query|execute|exec|prepare|raw|select|createNativeQuery|nativeQuery|prepareStatement|executeSql|runSql|db\.run|db\.all|db\.get|pool\.query|client\.query|conn\.query|connection\.query|sequelize\.query|knex\.raw|drizzle\.execute|prisma\.\$queryRaw)\s*[(`(]\s*"#,
            r#"("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)"#
        ))
        .unwrap()
    });

    let mut queries = Vec::new();

    for caps in SINK_PAT.captures_iter(content) {
        if let Some(arg) = caps.get(1) {
            let inner = strip_quote(arg.as_str());
            if is_likely_sql(inner.trim()) && !is_jpql(inner.trim()) {
                let (line, col) = offset_to_line_col(content, arg.start());
                let is_dynamic = match language {
                    "typescript" => inner.contains("${"),
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
    }

    queries
}
