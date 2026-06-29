use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Schema {
    pub tables: HashMap<String, Table>,
    pub dialect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub indexes: Vec<Index>,
    pub primary_key: Vec<String>,
    /// Partition columns, if any. Empty means not partitioned.
    #[serde(default)]
    pub partition_columns: Vec<String>,
    /// Estimated row count. None means unknown.
    #[serde(default)]
    pub estimated_rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub col_type: String,
    pub nullable: bool,
    pub primary_key: bool,
    pub foreign_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

impl Schema {
    pub fn has_table(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }

    pub fn get_table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }
}

impl Table {
    pub fn has_column(&self, name: &str) -> bool {
        self.columns
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(name))
    }

    pub fn has_index_on(&self, columns: &[String]) -> bool {
        self.indexes.iter().any(|idx| idx.columns == columns)
    }
}

/// Parse DDL SQL into a Schema.
pub fn parse_ddl(sql: &str, dialect: &str) -> Schema {
    use sqlparser::ast::*;
    use sqlparser::dialect::*;
    use sqlparser::parser::Parser;

    let dialect_obj: Box<dyn Dialect> = match dialect.to_lowercase().as_str() {
        "postgresql" | "postgres" => Box::new(PostgreSqlDialect {}),
        "mysql" => Box::new(MySqlDialect {}),
        "tsql" | "mssql" => Box::new(MsSqlDialect {}),
        "sqlite" => Box::new(SQLiteDialect {}),
        _ => Box::new(GenericDialect {}),
    };

    let mut schema = Schema {
        tables: HashMap::new(),
        dialect: dialect.to_string(),
    };

    let stmts = match Parser::parse_sql(dialect_obj.as_ref(), sql) {
        Ok(s) => s,
        Err(_) => return schema,
    };

    for stmt in &stmts {
        match stmt {
            Statement::CreateTable(create) => {
                let table_name = create.name.to_string();
                let mut columns = Vec::new();
                let mut pk_cols = Vec::new();

                for col_def in &create.columns {
                    let col_name = col_def.name.value.clone();
                    let col_type = col_def.data_type.to_string();

                    let mut nullable = true;
                    let mut is_pk = false;
                    let mut fk = None;

                    for option in &col_def.options {
                        match &option.option {
                            ColumnOption::NotNull => nullable = false,
                            ColumnOption::Unique { is_primary, .. } => {
                                if *is_primary {
                                    is_pk = true;
                                    nullable = false;
                                    pk_cols.push(col_name.clone());
                                }
                            }
                            ColumnOption::ForeignKey { foreign_table, .. } => {
                                fk = Some(foreign_table.to_string());
                            }
                            _ => {}
                        }
                    }

                    columns.push(crate::schema::Column {
                        name: col_name,
                        col_type,
                        nullable,
                        primary_key: is_pk,
                        foreign_key: fk,
                    });
                }

                // Check table-level constraints
                for constraint in &create.constraints {
                    if let TableConstraint::PrimaryKey {
                        columns: pk_columns,
                        ..
                    } = constraint
                    {
                        for c in pk_columns {
                            let name = c.to_string();
                            pk_cols.push(name.clone());
                            if let Some(col) = columns.iter_mut().find(|col| col.name == name) {
                                col.primary_key = true;
                                col.nullable = false;
                            }
                        }
                    }
                }

                schema.tables.insert(
                    table_name.clone(),
                    crate::schema::Table {
                        name: table_name,
                        columns,
                        indexes: Vec::new(),
                        primary_key: pk_cols,
                        partition_columns: Vec::new(),
                        estimated_rows: None,
                    },
                );
            }
            Statement::CreateIndex(create_idx) => {
                let table_name = create_idx.table_name.to_string();
                let index_name = create_idx
                    .name
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let cols: Vec<String> = create_idx.columns.iter().map(|c| c.to_string()).collect();
                let unique = create_idx.unique;

                if let Some(table) = schema.tables.get_mut(&table_name) {
                    table.indexes.push(crate::schema::Index {
                        name: index_name,
                        columns: cols,
                        unique,
                    });
                }
            }
            _ => {}
        }
    }

    schema
}

/// Load a schema from a DDL file.
pub fn load_schema_file(path: &Path, dialect: &str) -> Result<Schema, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read schema file {}: {}", path.display(), e))?;
    Ok(parse_ddl(&content, dialect))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create_table() {
        let ddl = "CREATE TABLE users (
            id INT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            name TEXT
        );";
        let schema = parse_ddl(ddl, "postgresql");
        assert!(schema.has_table("users"));
        let table = schema.get_table("users").unwrap();
        assert_eq!(table.columns.len(), 3);
        assert!(table.has_column("id"));
        assert!(table.has_column("email"));
        assert!(table.has_column("name"));
        assert!(!table.has_column("nonexistent"));
    }

    #[test]
    fn parse_primary_key() {
        let ddl = "CREATE TABLE users (id INT PRIMARY KEY, name TEXT);";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("users").unwrap();
        assert!(table.primary_key.contains(&"id".to_string()));
        let id_col = table.columns.iter().find(|c| c.name == "id").unwrap();
        assert!(id_col.primary_key);
        assert!(!id_col.nullable);
    }

    #[test]
    fn parse_not_null() {
        let ddl = "CREATE TABLE t (a INT NOT NULL, b TEXT);";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("t").unwrap();
        let a = table.columns.iter().find(|c| c.name == "a").unwrap();
        let b = table.columns.iter().find(|c| c.name == "b").unwrap();
        assert!(!a.nullable);
        assert!(b.nullable);
    }

    #[test]
    fn parse_create_index() {
        let ddl = "
            CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255));
            CREATE INDEX idx_email ON users (email);
        ";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("users").unwrap();
        assert_eq!(table.indexes.len(), 1);
        assert_eq!(table.indexes[0].name, "idx_email");
        assert!(table.has_index_on(&["email".to_string()]));
    }

    #[test]
    fn parse_multiple_tables() {
        let ddl = "
            CREATE TABLE users (id INT PRIMARY KEY);
            CREATE TABLE orders (id INT PRIMARY KEY, user_id INT);
        ";
        let schema = parse_ddl(ddl, "postgresql");
        assert!(schema.has_table("users"));
        assert!(schema.has_table("orders"));
    }

    #[test]
    fn nonexistent_table() {
        let schema = parse_ddl("CREATE TABLE t (id INT);", "postgresql");
        assert!(!schema.has_table("nonexistent"));
        assert!(schema.get_table("nonexistent").is_none());
    }

    #[test]
    fn parse_foreign_key() {
        let ddl = "CREATE TABLE orders (id INT PRIMARY KEY, user_id INT REFERENCES users(id));";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("orders").unwrap();
        let fk_col = table.columns.iter().find(|c| c.name == "user_id").unwrap();
        assert!(fk_col.foreign_key.is_some());
    }

    #[test]
    fn parse_table_level_primary_key() {
        let ddl = "CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b));";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("t").unwrap();
        assert!(table.primary_key.contains(&"a".to_string()));
        assert!(table.primary_key.contains(&"b".to_string()));
        let col_a = table.columns.iter().find(|c| c.name == "a").unwrap();
        assert!(col_a.primary_key);
        assert!(!col_a.nullable);
    }

    #[test]
    fn parse_mysql_dialect() {
        let ddl = "CREATE TABLE t (id INT PRIMARY KEY, name VARCHAR(100));";
        let schema = parse_ddl(ddl, "mysql");
        assert!(schema.has_table("t"));
    }

    #[test]
    fn parse_tsql_dialect() {
        let ddl = "CREATE TABLE t (id INT PRIMARY KEY);";
        let schema = parse_ddl(ddl, "tsql");
        assert!(schema.has_table("t"));
    }

    #[test]
    fn parse_sqlite_dialect() {
        let ddl = "CREATE TABLE t (id INTEGER PRIMARY KEY);";
        let schema = parse_ddl(ddl, "sqlite");
        assert!(schema.has_table("t"));
    }

    #[test]
    fn parse_generic_dialect() {
        let ddl = "CREATE TABLE t (id INT);";
        let schema = parse_ddl(ddl, "generic");
        assert!(schema.has_table("t"));
    }

    #[test]
    fn parse_invalid_sql() {
        let schema = parse_ddl("NOT VALID SQL AT ALL", "postgresql");
        assert!(schema.tables.is_empty());
    }

    #[test]
    fn load_schema_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schema.sql");
        std::fs::write(&path, "CREATE TABLE users (id INT PRIMARY KEY);").unwrap();
        let schema = load_schema_file(&path, "postgresql").unwrap();
        assert!(schema.has_table("users"));
    }

    #[test]
    fn load_schema_file_not_found() {
        let result = load_schema_file(std::path::Path::new("/nonexistent.sql"), "postgresql");
        assert!(result.is_err());
    }

    #[test]
    fn has_index_on_no_match() {
        let ddl = "CREATE TABLE t (id INT PRIMARY KEY);";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("t").unwrap();
        assert!(!table.has_index_on(&["nonexistent".to_string()]));
    }

    #[test]
    fn unique_index() {
        let ddl = "CREATE TABLE t (id INT PRIMARY KEY, email TEXT); CREATE UNIQUE INDEX idx ON t (email);";
        let schema = parse_ddl(ddl, "postgresql");
        let table = schema.get_table("t").unwrap();
        assert!(table.indexes[0].unique);
    }
}
