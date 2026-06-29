# Parser Engine

SlowQL uses the `sqlparser` Rust crate for SQL parsing alongside custom extractors for application code.

## SQL Parsing Pipeline
``` text
Raw SQL -> Statement Splitter -> Dialect Detector -> sqlparser -> Query Object
```

### Statement Splitter

Splits raw SQL content into individual statements using semicolon detection with awareness of:
- String literals (single-quoted, double-quoted, dollar-quoted)
- Block comments (`/* ... */`)
- Line comments (`--`)
- PostgreSQL dollar-quoted functions (`$$ ... $$`)

### Dialect Detection

If no dialect is configured, SlowQL detects it from SQL patterns:
- Backtick identifiers -> MySQL
- `@@` variables -> T-SQL
- `ROWNUM` -> Oracle
- `QUALIFY`, `VARIANT` -> Snowflake
- Backtick + `STRUCT<>` -> BigQuery
- Dollar-quoted strings -> PostgreSQL

### Query Object

Each parsed statement becomes a `Query` struct:

```Rust
pub struct Query {
    pub raw: String,           // Original SQL text
    pub normalized: String,    // Uppercase normalized form
    pub dialect: String,       // Detected or configured dialect
    pub location: Location,    // File, line, column
    pub tables: Vec<String>,   // Referenced table names
    pub columns: Vec<String>,  // Referenced column names
    pub query_type: Option<String>,  // SELECT, INSERT, UPDATE, DELETE, etc.
    pub is_ddl: bool,          // Is this a DDL statement?
    pub is_dynamic: bool,      // Contains template placeholders?
    pub complexity_score: u32, // 0-100 complexity score
    pub source_context: String, // application, migration, test, etc.
    pub facts: Option<QueryFacts>, // Structural facts (AST-level)
}
```

### QueryFacts
Structural facts extracted by deeper AST analysis:
``` Rust
pub struct QueryFacts {
    pub has_where: bool,
    pub has_limit: bool,
    pub has_aggregation: bool,
    pub has_group_by: bool,
    pub join_count: usize,
    pub from_tables: Vec<String>,
    pub subquery_count: usize,
}
```
Rules use facts to avoid regex false positives. For example, `PERF-SCAN-003` (unbounded SELECT) checks `facts.has_limit` instead of scanning for the word `LIMIT`.

## Application Code Extraction

For non-SQL files, language-specific extractors identify SQL sinks and extract string arguments:

- Python: triple-quote regex, f-string detection, single/double quote regex
- TypeScript/JavaScript: template literal regex, sink-aware pattern matching
- Java/Kotlin/C#: sink method regex
- Go: sink method regex with format string detection
- Ruby: sink method regex, heredoc detection
- MyBatis XML: full XML parser

Each extracted SQL string goes through `is_likely_sql()` validation before becoming a `Query` object. This filter rejects English prose, URL strings, route patterns, and other non-SQL content.

## Caching
Parsed results are cached by file content hash. Unchanged files are not re-parsed on subsequent runs. Cache is stored in `.slowql_cache/` by default.