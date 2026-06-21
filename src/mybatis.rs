//! MyBatis XML mapper parser.
//! Extracts SQL statements from MyBatis mapper XML files and marks
//! dynamic queries and unsafe interpolation patterns.

use crate::extractor::ExtractedQuery;

/// Parse a MyBatis XML mapper file and extract SQL statements.
pub fn parse_mybatis_xml(content: &str, file_path: &str) -> Vec<ExtractedQuery> {
    let mut queries = Vec::new();

    // Find all SQL statement tags
    let tags = ["select", "insert", "update", "delete", "sql"];

    for tag in &tags {
        let open_pattern = format!("<{}", tag);
        let close_pattern = format!("</{}>", tag);

        let mut search_from = 0;
        while let Some(open_pos) = content[search_from..].find(&open_pattern) {
            let abs_open = search_from + open_pos;

            // Find the end of the opening tag
            let tag_end = match content[abs_open..].find('>') {
                Some(p) => abs_open + p + 1,
                None => break,
            };

            // Check for self-closing tag
            if content[abs_open..tag_end].ends_with("/>") {
                search_from = tag_end;
                continue;
            }

            // Find matching close tag
            let close_pos = match content[tag_end..].find(&close_pattern) {
                Some(p) => tag_end + p,
                None => break,
            };

            let sql_body = &content[tag_end..close_pos];

            // Extract the id attribute
            let tag_attrs = &content[abs_open..tag_end];
            let _id = extract_attr(tag_attrs, "id").unwrap_or_default();

            // Clean the SQL: strip MyBatis XML tags but preserve structure
            let cleaned = clean_mybatis_sql(sql_body);
            let trimmed = cleaned.trim();

            if trimmed.is_empty() {
                search_from = close_pos + close_pattern.len();
                continue;
            }

            // Skip <sql> fragments that are just column lists or snippets,
            // not full SQL statements.
            if *tag == "sql" {
                let upper_trimmed = trimmed.to_uppercase();
                let has_statement = upper_trimmed.starts_with("SELECT")
                    || upper_trimmed.starts_with("INSERT")
                    || upper_trimmed.starts_with("UPDATE")
                    || upper_trimmed.starts_with("DELETE")
                    || upper_trimmed.starts_with("CREATE")
                    || upper_trimmed.starts_with("ALTER")
                    || upper_trimmed.starts_with("DROP");
                if !has_statement {
                    search_from = close_pos + close_pattern.len();
                    continue;
                }
            }

            // Detect dynamic content
            let has_dynamic_tags = sql_body.contains("<if")
                || sql_body.contains("<where")
                || sql_body.contains("<set")
                || sql_body.contains("<foreach")
                || sql_body.contains("<choose")
                || sql_body.contains("<when")
                || sql_body.contains("<otherwise")
                || sql_body.contains("<trim")
                || sql_body.contains("<bind");

            // Detect unsafe ${} interpolation
            let has_unsafe_interp = trimmed.contains("${");

            // Safe #{} is parameterized, replace with placeholder for analysis
            let sql_for_analysis = trimmed.replace("#{", ":").replace("}", "");

            // Calculate line number
            let line = content[..abs_open].matches('\n').count() as u32 + 1;
            let last_nl = content[..abs_open].rfind('\n').map(|p| p + 1).unwrap_or(0);
            let col = (abs_open - last_nl + 1) as u32;

            let is_dynamic = has_dynamic_tags || has_unsafe_interp;

            queries.push(ExtractedQuery {
                raw: sql_for_analysis.to_string(),
                line,
                column: col,
                file_path: file_path.to_string(),
                is_dynamic,
                language: "mybatis".to_string(),
            });

            // If unsafe ${} is present, also flag it separately for injection
            if has_unsafe_interp {
                queries.push(ExtractedQuery {
                    raw: trimmed.to_string(),
                    line,
                    column: col,
                    file_path: file_path.to_string(),
                    is_dynamic: true,
                    language: "mybatis".to_string(),
                });
            }

            search_from = close_pos + close_pattern.len();
        }
    }

    queries
}

/// Remove MyBatis XML tags from SQL body while preserving SQL structure.
fn clean_mybatis_sql(body: &str) -> String {
    let mut result = String::with_capacity(body.len());
    let mut i = 0;
    let bytes = body.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            // Skip XML tags
            if let Some(end) = body[i..].find('>') {
                let tag_content = &body[i..i + end + 1];
                // For <if>, <where>, <set> etc, just skip the tag
                // For </if>, </where> etc, also skip
                // But preserve whitespace/newline
                if !tag_content.starts_with("<!") {
                    result.push(' ');
                }
                i += end + 1;
            } else {
                result.push(body.as_bytes()[i] as char);
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    // Normalize whitespace
    let mut normalized = String::with_capacity(result.len());
    let mut last_was_space = false;
    for c in result.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                normalized.push(' ');
                last_was_space = true;
            }
        } else {
            normalized.push(c);
            last_was_space = false;
        }
    }

    normalized.trim().to_string()
}

/// Extract an attribute value from an XML tag string.
fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    if let Some(start) = tag.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = tag[value_start..].find('"') {
            return Some(tag[value_start..value_start + end].to_string());
        }
    }
    // Try single quotes
    let pattern = format!("{}='", attr_name);
    if let Some(start) = tag.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = tag[value_start..].find('\'') {
            return Some(tag[value_start..value_start + end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_select() {
        let xml = r#"<mapper><select id="findById">SELECT id, name FROM users WHERE id = #{id}</select></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert_eq!(queries.len(), 1);
        assert!(queries[0].raw.contains("SELECT id, name FROM users"));
        assert!(!queries[0].is_dynamic);
    }

    #[test]
    fn parse_unsafe_interpolation() {
        let xml = r#"<mapper><select id="search">SELECT * FROM users WHERE name LIKE ${term}</select></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        // One cleaned + one raw with ${}
        assert!(!queries.is_empty());
        assert!(queries.iter().any(|q| q.is_dynamic));
    }

    #[test]
    fn parse_dynamic_tags() {
        let xml = r#"<mapper><update id="updateUser">
            UPDATE users
            <set>
                <if test="name != null">name = #{name},</if>
                <if test="email != null">email = #{email},</if>
            </set>
            WHERE id = #{id}
        </update></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert_eq!(queries.len(), 1);
        assert!(queries[0].is_dynamic);
        assert!(queries[0].raw.contains("UPDATE users"));
        assert!(queries[0].raw.contains("WHERE"));
    }

    #[test]
    fn parse_multiple_statements() {
        let xml = r#"<mapper>
            <select id="findAll">SELECT * FROM users</select>
            <insert id="add">INSERT INTO users (name) VALUES (#{name})</insert>
            <delete id="remove">DELETE FROM users WHERE id = #{id}</delete>
        </mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert_eq!(queries.len(), 3);
    }

    #[test]
    fn parse_where_tag() {
        let xml = r#"<mapper><select id="filter">
            SELECT * FROM users
            <where>
                <if test="name != null">AND name = #{name}</if>
                <if test="status != null">AND status = #{status}</if>
            </where>
        </select></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert_eq!(queries.len(), 1);
        assert!(queries[0].is_dynamic);
        assert!(queries[0].raw.contains("SELECT * FROM users"));
    }

    #[test]
    fn parse_sql_fragment() {
        let xml = r#"<mapper><sql id="cols">id, name, email</sql></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert_eq!(
            queries.len(),
            0,
            "sql fragments without SQL structure should not extract"
        );
    }

    #[test]
    fn parse_unsafe_table_name() {
        let xml = r#"<mapper><select id="bad">SELECT * FROM ${tableName} WHERE id = #{id}</select></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert!(queries
            .iter()
            .any(|q| q.is_dynamic && q.raw.contains("${tableName}")));
    }

    #[test]
    fn empty_mapper() {
        let xml = r#"<mapper></mapper>"#;
        let queries = parse_mybatis_xml(xml, "UserMapper.xml");
        assert!(queries.is_empty());
    }
}
