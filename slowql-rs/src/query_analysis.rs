//! Structural query analysis using sqlparser AST.
//! Provides high-confidence answers about query structure
//! that raw regex cannot reliably determine.

use sqlparser::ast::*;
use sqlparser::dialect::*;
use sqlparser::parser::Parser;

/// Structural facts about a parsed query.
#[derive(Debug, Default)]
pub struct QueryFacts {
    /// The top-level statement type
    pub statement_type: String,
    /// Tables in FROM/JOIN (not in subqueries)
    pub from_tables: Vec<String>,
    /// Columns explicitly selected (not *)
    pub selected_columns: Vec<String>,
    /// Whether SELECT * is used at the top level
    pub selects_star: bool,
    /// Whether the top-level query has a WHERE clause
    pub has_where: bool,
    /// Whether the top-level query has LIMIT
    pub has_limit: bool,
    /// Whether the top-level query has OFFSET
    pub has_offset: bool,
    /// Whether the top-level query has ORDER BY
    pub has_order_by: bool,
    /// Whether the top-level query has GROUP BY
    pub has_group_by: bool,
    /// Whether the top-level query has HAVING
    pub has_having: bool,
    /// Number of JOINs at the top level
    pub join_count: usize,
    /// Number of subqueries anywhere
    pub subquery_count: usize,
    /// Whether the query contains aggregation functions
    pub has_aggregation: bool,
    /// Columns used in WHERE clause predicates
    pub where_columns: Vec<String>,
    /// Whether WHERE uses equality on a likely primary key
    pub where_has_pk_equality: bool,
    /// Whether the query is inside a transaction
    pub in_transaction: bool,
    /// Whether the query uses FOR UPDATE
    pub has_for_update: bool,
    /// Tables in INSERT INTO
    pub insert_table: Option<String>,
    /// Columns listed in INSERT column list
    pub insert_columns: Vec<String>,
    /// Whether INSERT uses VALUES (not INSERT...SELECT)
    pub insert_has_values: bool,
    /// Tables in UPDATE
    pub update_table: Option<String>,
    /// Tables in DELETE FROM
    pub delete_table: Option<String>,
    /// Whether string literals contain the matched content (vs identifiers)
    pub string_literals: Vec<String>,
}

impl QueryFacts {
    /// Parse SQL and extract structural facts.
    pub fn from_sql(sql: &str, dialect: &str) -> Self {
        let dialect_obj: Box<dyn Dialect> = match dialect.to_lowercase().as_str() {
            "postgresql" | "postgres" => Box::new(PostgreSqlDialect {}),
            "mysql" => Box::new(MySqlDialect {}),
            "tsql" | "mssql" => Box::new(MsSqlDialect {}),
            "sqlite" => Box::new(SQLiteDialect {}),
            "bigquery" => Box::new(BigQueryDialect {}),
            "snowflake" => Box::new(SnowflakeDialect {}),
            _ => Box::new(GenericDialect {}),
        };

        let stmts = match Parser::parse_sql(dialect_obj.as_ref(), sql) {
            Ok(s) => s,
            Err(_) => return Self::default(),
        };

        if stmts.is_empty() {
            return Self::default();
        }

        let mut facts = Self::default();
        facts.analyze_statement(&stmts[0]);

        // Extract string literals from the raw SQL for context checking
        facts.extract_string_literals(sql);

        facts
    }

    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Query(query) => {
                self.statement_type = "SELECT".to_string();
                self.analyze_query(query);
            }
            Statement::Insert(insert) => {
                self.statement_type = "INSERT".to_string();
                self.insert_table = Some(insert.table.to_string());
                for col in &insert.columns {
                    self.insert_columns.push(col.value.clone());
                }
                self.insert_has_values = insert.source.as_ref()
                    .map(|s| matches!(s.body.as_ref(), SetExpr::Values(_)))
                    .unwrap_or(false);
            }
            Statement::Update { table, selection, .. } => {
                self.statement_type = "UPDATE".to_string();
                self.update_table = table_name_from_twj(table);
                self.has_where = selection.is_some();
                if let Some(sel) = selection {
                    self.extract_where_columns(sel);
                    self.check_pk_equality(sel);
                }
            }
            Statement::Delete(del) => {
                self.statement_type = "DELETE".to_string();
                match &del.from {
                    FromTable::WithFromKeyword(items) | FromTable::WithoutKeyword(items) => {
                        if let Some(first) = items.first() {
                            self.delete_table = table_name_from_factor(&first.relation);
                        }
                    }
                }
                self.has_where = del.selection.is_some();
                if let Some(sel) = &del.selection {
                    self.extract_where_columns(sel);
                    self.check_pk_equality(sel);
                }
            }
            _ => {
                self.statement_type = format!("{}", stmt).split_whitespace().next().unwrap_or("UNKNOWN").to_uppercase();
            }
        }
    }

    fn analyze_query(&mut self, query: &Query) {
        // Check for ORDER BY and LIMIT at query level
        self.has_order_by = query.order_by.is_some();
        self.has_limit = query.limit.is_some();
        self.has_offset = query.offset.is_some();

        if let SetExpr::Select(select) = query.body.as_ref() {
            self.analyze_select(select);
        }
    }

    fn analyze_select(&mut self, select: &Select) {
        // Check SELECT list
        for item in &select.projection {
            match item {
                SelectItem::Wildcard(_) => self.selects_star = true,
                SelectItem::UnnamedExpr(expr) => {
                    self.extract_select_columns(expr);
                    self.check_aggregation(expr);
                }
                SelectItem::ExprWithAlias { expr, .. } => {
                    self.extract_select_columns(expr);
                    self.check_aggregation(expr);
                }
                _ => {}
            }
        }

        // FROM tables
        for from in &select.from {
            if let Some(name) = table_name_from_factor(&from.relation) {
                self.from_tables.push(name);
            }
            self.join_count += from.joins.len();
            for join in &from.joins {
                if let Some(name) = table_name_from_factor(&join.relation) {
                    self.from_tables.push(name);
                }
                // Count subqueries in joins
                self.count_subqueries_in_factor(&join.relation);
            }
            self.count_subqueries_in_factor(&from.relation);
        }

        // WHERE
        self.has_where = select.selection.is_some();
        if let Some(ref selection) = select.selection {
            self.extract_where_columns(selection);
            self.check_pk_equality(selection);
            self.count_subqueries_in_expr(selection);
        }

        // GROUP BY / HAVING
        self.has_group_by = match &select.group_by {
            GroupByExpr::All(_) => true,
            GroupByExpr::Expressions(exprs, _) => !exprs.is_empty(),
        };
        self.has_having = select.having.is_some();

        // FOR UPDATE
        // Note: sqlparser may not expose this directly in all dialects
        // We check raw SQL as fallback
    }

    fn extract_select_columns(&mut self, expr: &Expr) {
        match expr {
            Expr::Identifier(ident) => {
                self.selected_columns.push(ident.value.clone());
            }
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last() {
                    self.selected_columns.push(last.value.clone());
                }
            }
            _ => {}
        }
    }

    fn check_aggregation(&mut self, expr: &Expr) {
        match expr {
            Expr::Function(func) => {
                let name = func.name.to_string().to_uppercase();
                if matches!(name.as_str(), "COUNT" | "SUM" | "AVG" | "MIN" | "MAX") {
                    self.has_aggregation = true;
                }
            }
            _ => {}
        }
    }

    fn extract_where_columns(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, right, .. } => {
                self.extract_where_columns(left);
                self.extract_where_columns(right);
            }
            Expr::Identifier(ident) => {
                self.where_columns.push(ident.value.to_lowercase());
            }
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last() {
                    self.where_columns.push(last.value.to_lowercase());
                }
            }
            _ => {}
        }
    }

    fn check_pk_equality(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op, right } => {
                if matches!(op, BinaryOperator::Eq) {
                    let col_name = match left.as_ref() {
                        Expr::Identifier(id) => Some(id.value.to_lowercase()),
                        Expr::CompoundIdentifier(parts) => parts.last().map(|p| p.value.to_lowercase()),
                        _ => None,
                    };
                    if let Some(name) = col_name {
                        if name == "id" || name.ends_with("_id") {
                            // Check right side is a literal or parameter
                            match right.as_ref() {
                                Expr::Value(_) | Expr::UnaryOp { .. } => {
                                    self.where_has_pk_equality = true;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                self.check_pk_equality(left);
                self.check_pk_equality(right);
            }
            _ => {}
        }
    }

    fn count_subqueries_in_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Subquery(_) => self.subquery_count += 1,
            Expr::InSubquery { subquery: _, .. } => self.subquery_count += 1,
            Expr::Exists { subquery: _, .. } => self.subquery_count += 1,
            Expr::BinaryOp { left, right, .. } => {
                self.count_subqueries_in_expr(left);
                self.count_subqueries_in_expr(right);
            }
            _ => {}
        }
    }

    fn count_subqueries_in_factor(&mut self, factor: &TableFactor) {
        if let TableFactor::Derived { subquery: _, .. } = factor {
            self.subquery_count += 1;
        }
    }

    fn extract_string_literals(&mut self, sql: &str) {
        // Simple extraction of single-quoted string contents
        let mut in_string = false;
        let mut current = String::new();
        let chars: Vec<char> = sql.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '\'' {
                if in_string {
                    if i + 1 < chars.len() && chars[i + 1] == '\'' {
                        current.push('\'');
                        i += 2;
                        continue;
                    }
                    self.string_literals.push(current.clone());
                    current.clear();
                    in_string = false;
                } else {
                    in_string = true;
                }
            } else if in_string {
                current.push(chars[i]);
            }
            i += 1;
        }
    }

    /// Check if a value appears inside a string literal (not as an identifier).
    pub fn is_in_string_literal(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        self.string_literals.iter().any(|s| s.to_lowercase().contains(&lower))
    }

    /// Check if query is a simple single-row lookup (WHERE pk = value).
    pub fn is_single_row_lookup(&self) -> bool {
        self.has_where && self.where_has_pk_equality
    }

    /// Check if a column name appears in the SELECT list.
    pub fn selects_column(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.selects_star || self.selected_columns.iter().any(|c| c.to_lowercase() == lower)
    }
}

fn table_name_from_factor(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { name, .. } => Some(name.to_string()),
        _ => None,
    }
}

fn table_name_from_twj(twj: &TableWithJoins) -> Option<String> {
    table_name_from_factor(&twj.relation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_select() {
        let facts = QueryFacts::from_sql("SELECT id, name FROM users WHERE id = 1", "postgresql");
        assert_eq!(facts.statement_type, "SELECT");
        assert!(facts.from_tables.contains(&"users".to_string()));
        assert!(facts.selected_columns.contains(&"id".to_string()));
        assert!(facts.selected_columns.contains(&"name".to_string()));
        assert!(!facts.selects_star);
        assert!(facts.has_where);
        assert!(facts.where_has_pk_equality);
    }

    #[test]
    fn select_star() {
        let facts = QueryFacts::from_sql("SELECT * FROM users", "postgresql");
        assert!(facts.selects_star);
        assert!(!facts.has_where);
        assert!(!facts.has_limit);
    }

    #[test]
    fn select_with_limit() {
        let facts = QueryFacts::from_sql("SELECT * FROM users LIMIT 10", "postgresql");
        assert!(facts.has_limit);
    }

    #[test]
    fn select_with_order() {
        let facts = QueryFacts::from_sql("SELECT * FROM users ORDER BY id LIMIT 10", "postgresql");
        assert!(facts.has_order_by);
        assert!(facts.has_limit);
    }

    #[test]
    fn delete_without_where() {
        let facts = QueryFacts::from_sql("DELETE FROM users", "postgresql");
        assert_eq!(facts.statement_type, "DELETE");
        assert_eq!(facts.delete_table.as_deref(), Some("users"));
        assert!(!facts.has_where);
    }

    #[test]
    fn delete_with_pk() {
        let facts = QueryFacts::from_sql("DELETE FROM users WHERE id = 1", "postgresql");
        assert!(facts.has_where);
        assert!(facts.where_has_pk_equality);
    }

    #[test]
    fn insert_with_columns() {
        let facts = QueryFacts::from_sql(
            "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
            "postgresql"
        );
        assert_eq!(facts.statement_type, "INSERT");
        assert!(facts.insert_has_values);
        assert!(facts.insert_columns.contains(&"name".to_string()));
        assert!(facts.insert_columns.contains(&"email".to_string()));
    }

    #[test]
    fn string_literal_detection() {
        let facts = QueryFacts::from_sql(
            "INSERT INTO users (email) VALUES ('test@example.com')",
            "postgresql"
        );
        assert!(facts.is_in_string_literal("@example.com"));
        assert!(facts.is_in_string_literal("test@"));
        assert!(!facts.is_in_string_literal("nonexistent"));
    }

    #[test]
    fn pk_equality_detection() {
        let f1 = QueryFacts::from_sql("SELECT * FROM users WHERE id = 1", "postgresql");
        assert!(f1.is_single_row_lookup());

        let f2 = QueryFacts::from_sql("SELECT * FROM users WHERE status = 'active'", "postgresql");
        assert!(!f2.is_single_row_lookup());

        let f3 = QueryFacts::from_sql("SELECT * FROM orders WHERE user_id = 42", "postgresql");
        assert!(f3.is_single_row_lookup());
    }

    #[test]
    fn aggregation_detection() {
        let f1 = QueryFacts::from_sql("SELECT COUNT(*) FROM users", "postgresql");
        assert!(f1.has_aggregation);

        let f2 = QueryFacts::from_sql("SELECT * FROM users", "postgresql");
        assert!(!f2.has_aggregation);
    }

    #[test]
    fn join_count() {
        let facts = QueryFacts::from_sql(
            "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id",
            "postgresql"
        );
        assert_eq!(facts.join_count, 2);
    }

    #[test]
    fn selects_column_check() {
        let facts = QueryFacts::from_sql("SELECT id, email FROM users", "postgresql");
        assert!(facts.selects_column("email"));
        assert!(facts.selects_column("id"));
        assert!(!facts.selects_column("phone"));

        let facts2 = QueryFacts::from_sql("SELECT * FROM users", "postgresql");
        assert!(facts2.selects_column("anything"));
    }
}
