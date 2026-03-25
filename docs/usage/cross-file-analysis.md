# Cross-File SQL Analysis

SlowQL goes beyond single-file analysis by understanding relationships between multiple SQL files, DDL definitions, views, and stored procedures. This enables the detection of "breaking changes" where a schema modification in one file would cause queries in another file to fail.

## How it Works

When analyzing a project (a directory of SQL files), SlowQL performs a two-pass analysis:

1.  **First Pass (Collection):** SlowQL parses all files and builds a comprehensive schema model, including all tables, columns, views, and stored procedures.
2.  **Second Pass (Validation):** It then runs cross-file rules that compare the aggregated schema against individual queries to find regressions.

## Key Capabilities

### 1. Breaking DDL Change Detection

The most powerful feature of cross-file analysis is detecting when a DDL operation (like `DROP COLUMN` or `DROP TABLE`) breaks an existing query in a different file.

**Example:**
- `schema.sql`: `ALTER TABLE users DROP COLUMN email;`
- `app_queries.sql`: `SELECT email FROM users;`

In isolation, both files might look syntactically valid. However, SlowQL flags the `ALTER` statement as a breaking change (`SCH-BRK-001`) because it invalidates the `SELECT` query in `app_queries.sql`.

### 2. View Dependency Tracking

SlowQL tracks dependencies between views and the tables (or other views) they reference. This ensures that if a base table is modified, SlowQL can identify all affected downstream views.

### 3. Stored Procedure Call Graphs

SlowQL analyzes stored procedure bodies to extract `CALL` and `EXEC` statements, building a call graph. This allows it to detect:
- Calls to non-existent procedures.
- Breaking changes in procedure signatures.
- Deeply nested or circular dependencies.

## Usage

Cross-file analysis is enabled by default when you provide a directory as input:

```bash
# Analyzes all .sql files in the directory and checks for cross-file regressions
slowql ./project/sql/
```

### Rule Reference

| Rule ID | Name | Description |
|---------|------|-------------|
| `SCH-BRK-001` | Breaking DDL Change | Detected a schema change that invalidates queries in other files. |
| `SCH-DEP-001` | Missing View Dependency | A view references a table or view not found in the project. |
| `SCH-PRC-001` | Invalid Procedure Call | A stored procedure calls a procedure that is not defined. |

## Performance and Caching

Cross-file analysis requires a full scan of the project. To maintain high performance, SlowQL uses its **Hash-Based Caching** system. If a file hasn't changed, SlowQL reuses its previous AST and metadata, significantly speeding up subsequent cross-file scans.

```bash
# Clear cache if you want to force a full re-analysis
slowql ./project/sql/ --clear-cache
```
