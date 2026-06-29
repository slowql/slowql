# System Design

SlowQL is a single-pass SQL static analyzer written in Rust.

## Pipeline
``` text
Files -> Walker -> Context Classifier -> Parser -> Rule Engine -> Issues -> Reporter
| | |
Extractor Schema Autofix
(app code) Validator (safe only)
```

## Components

### Walker (`cli.rs`)
Traverses directories recursively. Filters by supported file extensions (.sql, .py, .ts, .js, .java, .go, .rb, .kt, .cs, .xml). Skips non-UTF-8 files.

### Context Classifier (`context.rs`)
Classifies each file by its role in the project based on path patterns and content analysis. Returns one of: `application`, `migration`, `test`, `seed`, `example`, `framework_internal`, `ddl_schema`, `dbt_model`, `adhoc`.

Rules are filtered based on context. Non-production contexts only allow security and reliability rules.

### Parser (`parser.rs`)
Splits SQL content into individual statements. Detects dialect from SQL patterns. Extracts table names, column names, and query type. Uses the `sqlparser` crate for structural parsing.

### Extractor (`extractor.rs`)
Extracts SQL strings from application source code:
- Python: triple-quoted strings, f-strings
- TypeScript/JavaScript: template literals, sink-aware regex
- Java/Kotlin: prepareStatement, createNativeQuery
- Go: db.Query, db.Exec
- Ruby: connection.execute, heredocs
- C#: connection.Execute

Each extractor uses language-specific patterns to identify SQL sinks and extract the SQL string content.

### Rule Engine (`engine.rs`)
Iterates all parsed queries through all enabled rules. Applies:
- Dimension filtering (enabled_dimensions config)
- Rule enable/disable lists
- Severity overrides
- Confidence demotion for templated queries
- Context-based filtering
- Inline suppression

### Rules (`rules/`)
282+ rules across 8 modules: security, performance, reliability, quality, cost, compliance, migration, schema. Each rule implements the `Rule` trait with id, name, severity, dimension, confidence, and check method.

### Schema Validator (`schema.rs`)
Parses DDL files into a schema model. Validates table and column references against the schema.

### Project Analyzer (`project.rs`)
Cross-file analysis after individual file analysis:
- Duplicate query detection (HashMap-based, O(Q))
- Cross-file breaking changes (indexed lookups, O(Q + T))
- Unused object detection (definition/reference matching)

### Autofix (`autofixer.rs`)
Conservative text-replacement fixes. Only applies fixes tagged as `FixConfidence::Safe`. Creates .bak backups.

### Reporter (`cli.rs`)
Outputs results in console, JSON, SARIF 2.1.0, or GitHub Actions annotation format. Supports HTML, CSV, and JSON file exports.

## Performance Characteristics

- Per-query rule execution: O(rules * query_length)
- Project-level analysis: O(Q) with HashMap indexing
- Context classification: O(1) per file (regex matching)
- Memory: proportional to total query count and raw SQL size
- Skips project-level analysis for corpora exceeding 20,000 queries

## Confidence Architecture

Every rule declares a confidence level:

- **Proven**: The finding is structurally deterministic. No false positives possible from the SQL text alone.
- **Contextual**: The finding is accurate when context (schema, file role, runtime environment) is available. May need human verification.
- **Advisory**: The finding is a style preference or best practice. Not provably wrong.

Default mode is `proven`. Users opt into lower confidence levels explicitly.