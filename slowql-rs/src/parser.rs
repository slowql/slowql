use crate::models::issue::Location;
use crate::models::query::Query;
use sqlparser::ast::{self, Statement};
use sqlparser::dialect::*;
use sqlparser::parser::Parser as SqlParser;

fn get_dialect(dialect: &str) -> Box<dyn Dialect> {
    match dialect.to_lowercase().as_str() {
        "postgresql" | "postgres" | "pg" => Box::new(PostgreSqlDialect {}),
        "mysql" | "mariadb" => Box::new(MySqlDialect {}),
        "tsql" | "mssql" | "sqlserver" | "sql_server" => Box::new(MsSqlDialect {}),
        "sqlite" => Box::new(SQLiteDialect {}),
        "bigquery" | "bq" => Box::new(BigQueryDialect {}),
        "snowflake" | "sf" => Box::new(SnowflakeDialect {}),
        "redshift" => Box::new(RedshiftSqlDialect {}),
        "clickhouse" => Box::new(ClickHouseDialect {}),
        "duckdb" => Box::new(DuckDbDialect {}),
        "hive" | "spark" | "databricks" => Box::new(HiveDialect {}),
        _ => Box::new(GenericDialect {}),
    }
}

fn statement_type(stmt: &Statement) -> Option<String> {
    match stmt {
        Statement::Query(_) => Some("SELECT".into()),
        Statement::Insert(_) => Some("INSERT".into()),
        Statement::Update { .. } => Some("UPDATE".into()),
        Statement::Delete(_) => Some("DELETE".into()),
        Statement::CreateTable(_) => Some("CREATE".into()),
        Statement::CreateView { .. } => Some("CREATE".into()),
        Statement::CreateIndex(_) => Some("CREATE".into()),
        Statement::AlterTable { .. } => Some("ALTER".into()),
        Statement::Drop { .. } => Some("DROP".into()),
        Statement::Truncate { .. } => Some("TRUNCATE".into()),
        Statement::Merge { .. } => Some("MERGE".into()),
        Statement::Grant { .. } => Some("GRANT".into()),
        Statement::Revoke { .. } => Some("REVOKE".into()),
        _ => {
            let s = format!("{stmt}");
            let first_word = s.split_whitespace().next().unwrap_or("");
            if first_word.is_empty() {
                None
            } else {
                Some(first_word.to_uppercase())
            }
        }
    }
}

fn is_ddl(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::CreateTable(_)
            | Statement::CreateView { .. }
            | Statement::CreateIndex(_)
            | Statement::AlterTable { .. }
            | Statement::Drop { .. }
            | Statement::Truncate { .. }
    )
}

fn extract_tables(stmt: &Statement) -> Vec<String> {
    let mut tables = Vec::new();

    if let Statement::Query(q) = stmt {
        collect_tables_from_query(q, &mut tables);
    }

    match stmt {
        Statement::Insert(insert) => {
            if let Some(name) = table_name_from_table_object(&insert.table) {
                tables.push(name);
            }
        }
        Statement::Update { table, .. } => {
            if let Some(name) = table_name_from_table_with_joins(table) {
                tables.push(name);
            }
        }
        Statement::Delete(del) => match &del.from {
            ast::FromTable::WithFromKeyword(items) | ast::FromTable::WithoutKeyword(items) => {
                for twj in items {
                    if let Some(name) = table_name_from_table_factor(&twj.relation) {
                        tables.push(name);
                    }
                }
            }
        },
        Statement::CreateTable(create) => {
            tables.push(create.name.to_string());
        }
        Statement::CreateView { name, .. } => {
            tables.push(name.to_string());
        }
        Statement::CreateIndex(idx) => {
            tables.push(idx.table_name.to_string());
        }
        _ => {}
    }

    tables.sort();
    tables.dedup();
    tables
}

fn collect_tables_from_query(q: &ast::Query, tables: &mut Vec<String>) {
    if let ast::SetExpr::Select(sel) = q.body.as_ref() {
        for from_item in &sel.from {
            if let Some(name) = table_name_from_table_factor(&from_item.relation) {
                tables.push(name);
            }
            for join in &from_item.joins {
                if let Some(name) = table_name_from_table_factor(&join.relation) {
                    tables.push(name);
                }
            }
        }
    }
}

fn table_name_from_table_factor(tf: &ast::TableFactor) -> Option<String> {
    match tf {
        ast::TableFactor::Table { name, .. } => Some(name.to_string()),
        _ => None,
    }
}

fn table_name_from_table_object(obj: &ast::TableObject) -> Option<String> {
    match obj {
        ast::TableObject::TableName(name) => Some(name.to_string()),
        ast::TableObject::TableFunction(_) => None,
    }
}

fn table_name_from_table_with_joins(twj: &ast::TableWithJoins) -> Option<String> {
    table_name_from_table_factor(&twj.relation)
}

fn extract_columns(stmt: &Statement) -> Vec<String> {
    let mut cols = Vec::new();

    if let Statement::Query(q) = stmt {
        if let ast::SetExpr::Select(sel) = q.body.as_ref() {
            for item in &sel.projection {
                match item {
                    ast::SelectItem::UnnamedExpr(ast::Expr::Identifier(id)) => {
                        cols.push(id.value.clone());
                    }
                    ast::SelectItem::ExprWithAlias {
                        expr: ast::Expr::Identifier(id),
                        ..
                    } => {
                        cols.push(id.value.clone());
                    }
                    ast::SelectItem::Wildcard(_) => {
                        cols.push("*".into());
                    }
                    _ => {}
                }
            }
        }
    }

    cols
}

fn offset_to_location(
    src: &str,
    offset: usize,
    file_path: Option<&str>,
    query_index: usize,
) -> Location {
    let bytes = src.as_bytes();
    let safe_offset = offset.min(src.len());

    let mut line: u32 = 1;
    let mut last_newline: usize = 0;

    for (i, &b) in bytes[..safe_offset].iter().enumerate() {
        if b == b'\n' {
            line += 1;
            last_newline = i + 1;
        }
    }

    let column = (safe_offset - last_newline + 1) as u32;

    let mut loc = Location::new(line, column);
    if let Some(f) = file_path {
        loc = loc.with_file(f);
    }
    loc.with_query_index(query_index)
}

fn split_statements(sql: &str) -> Vec<(usize, usize)> {
    let bytes = sql.as_bytes();
    let len = bytes.len();

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    let mut stmt_start: Option<usize> = None;

    while i < len {
        let b = bytes[i];

        match b {
            b'\'' => {
                if stmt_start.is_none() {
                    stmt_start = Some(i);
                }
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < len && bytes[i] == b'\'' {
                            i += 1;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            b'"' => {
                if stmt_start.is_none() {
                    stmt_start = Some(i);
                }
                i += 1;
                while i < len && bytes[i] != b'"' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'-' if i + 1 < len && bytes[i + 1] == b'-' => {
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < len {
                    i += 2;
                } else {
                    i = len;
                }
            }
            b';' => {
                if let Some(start) = stmt_start {
                    ranges.push((start, i));
                }
                stmt_start = None;
                i += 1;
            }
            b if b.is_ascii_whitespace() => {
                i += 1;
            }
            _ => {
                if stmt_start.is_none() {
                    stmt_start = Some(i);
                }
                i += 1;
            }
        }
    }

    if let Some(start) = stmt_start {
        let end = sql.trim_end().len();
        if end > start {
            ranges.push((start, end));
        }
    }

    ranges
}

pub fn parse(sql: &str, dialect: &str, file_path: Option<&str>) -> Vec<Query> {
    let effective_dialect = if dialect.is_empty() || dialect == "unknown" {
        detect_dialect(sql)
    } else {
        dialect.to_string()
    };

    let stripped_sql = crate::jinja::strip_jinja(sql);
    let stmt_ranges = split_statements(&stripped_sql);
    let mut queries = Vec::with_capacity(stmt_ranges.len());

    for (idx, &(start, end)) in stmt_ranges.iter().enumerate() {
        let raw = &sql[start..end];
        let trimmed = stripped_sql[start..end].trim();
        if trimmed.is_empty() {
            continue;
        }

        let dialect_obj = get_dialect(&effective_dialect);
        let location = offset_to_location(sql, start, file_path, idx);

        let parsed = SqlParser::parse_sql(dialect_obj.as_ref(), trimmed);

        let (query_type, tables, columns, is_ddl_flag, normalized) = match &parsed {
            Ok(stmts) if !stmts.is_empty() => {
                let stmt = &stmts[0];
                (
                    statement_type(stmt),
                    extract_tables(stmt),
                    extract_columns(stmt),
                    is_ddl(stmt),
                    stmt.to_string(),
                )
            }
            _ => {
                let qt = detect_query_type(trimmed);
                let is_ddl_f = matches!(
                    qt.as_deref(),
                    Some("CREATE") | Some("ALTER") | Some("DROP") | Some("TRUNCATE")
                );
                (qt, vec![], vec![], is_ddl_f, trimmed.to_string())
            }
        };

        queries.push(Query {
            raw: raw.to_string(),
            normalized,
            dialect: effective_dialect.clone(),
            location,
            start_offset: Some(start),
            end_offset: Some(end),
            tables,
            columns,
            query_type,
            is_ddl: is_ddl_flag,
            is_dynamic: false,
            complexity_score: 0,
            source_context: String::new(),
            ..Default::default()
        });
    }

    queries
}

fn detect_query_type(sql: &str) -> Option<String> {
    let trimmed = sql.trim_start();
    let upper = trimmed.to_uppercase();

    for kw in &[
        "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE",
        "MERGE", "GRANT", "REVOKE", "WITH",
    ] {
        if upper.starts_with(kw) {
            return Some(if *kw == "WITH" {
                "SELECT".into()
            } else {
                kw.to_string()
            });
        }
    }

    None
}

fn detect_dialect(sql: &str) -> String {
    let upper = sql.to_uppercase();

    if upper.contains("::") || upper.contains("$1") {
        "postgresql".into()
    } else if upper.contains("LIMIT ") && upper.contains('`') {
        "mysql".into()
    } else if (upper.contains('[') && upper.contains(']')) || upper.contains("TOP ") {
        "tsql".into()
    } else if upper.contains("ROWNUM") {
        "oracle".into()
    } else if upper.contains("LATERAL FLATTEN") {
        "snowflake".into()
    } else {
        "generic".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_select() {
        let queries = parse("SELECT id, name FROM users WHERE id = 1", "postgresql", None);
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].query_type.as_deref(), Some("SELECT"));
        assert!(queries[0].tables.contains(&"users".to_string()));
    }

    #[test]
    fn parse_multiple_statements() {
        let sql = "SELECT 1; DELETE FROM users; INSERT INTO t VALUES (1)";
        let queries = parse(sql, "postgresql", None);
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].query_type.as_deref(), Some("SELECT"));
        assert_eq!(queries[1].query_type.as_deref(), Some("DELETE"));
        assert_eq!(queries[2].query_type.as_deref(), Some("INSERT"));
    }

    #[test]
    fn parse_preserves_location() {
        let sql = "SELECT 1;\n\nDELETE FROM t";
        let queries = parse(sql, "postgresql", Some("test.sql"));
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].location.line, 1);
        assert_eq!(queries[1].location.line, 3);
        assert_eq!(queries[1].location.file.as_deref(), Some("test.sql"));
    }

    #[test]
    fn parse_handles_string_with_semicolon() {
        let sql = "SELECT * FROM t WHERE name = 'hello;world'";
        let queries = parse(sql, "postgresql", None);
        assert_eq!(queries.len(), 1);
    }

    #[test]
    fn parse_handles_comments() {
        let sql = "-- comment\nSELECT 1; /* block */ SELECT 2";
        let queries = parse(sql, "postgresql", None);
        assert_eq!(queries.len(), 2);
    }

    #[test]
    fn detect_ddl() {
        let sql = "CREATE TABLE users (id INT PRIMARY KEY)";
        let queries = parse(sql, "postgresql", None);
        assert_eq!(queries.len(), 1);
        assert!(queries[0].is_ddl);
        assert_eq!(queries[0].query_type.as_deref(), Some("CREATE"));
    }
}
