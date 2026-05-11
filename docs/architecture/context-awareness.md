# Context-Aware Analysis

SlowQL automatically classifies every SQL file into a **source context** and filters its analysis accordingly. This eliminates false positives without requiring manual suppression - migration files will not flag SELECT *, test files will not warn about missing LIMIT, and application code will not suggest dbt ref() syntax.

## Why Context Matters

A SELECT * in a migration is routine. The same query in production application code is a performance risk. Without context awareness, a linter treats both identically - either flooding migrations with noise or missing real issues in application code.

SlowQL solves this by classifying each file before analysis and applying context-specific filtering.

## Supported Contexts

| Context | Classification Method | Filtering |
|---------|----------------------|-----------|
| migration | Path: migrations/, alembic/versions/, db/migrate/, flyway/, liquibase/, prisma/migrations/ | Allowlist: SEC-, REL- only |
| test | Path: tests/, spec/, __tests__/, or filename *test*.sql | Allowlist: SEC-, REL- only |
| seed | Path: seeds/, fixtures/ | Allowlist: SEC-, REL- only |
| ddl_schema | Path: schema.sql, schema/, ddl/ | Allowlist: SEC-, REL-, COMP- |
| dbt_model | Path: models/*.sql, dbt_models/ | Full analysis (deny: PERF-SCAN-003) |
| application | Path: src/, content heuristics | Full analysis (deny: QUAL-DBT-*) |
| adhoc | No file path, or unrecognized path | Full analysis (deny: QUAL-DBT-*) |
| view_def | Content: CREATE OR REPLACE VIEW | Full analysis |
| stored_proc | Content: CREATE PROCEDURE/CREATE FUNCTION | Full analysis |

## Three-Layer Filtering

SlowQL applies three layers of filtering to achieve 100% precision:

### Layer 1: Allowlist

Non-production contexts (migration, test, seed, ddl_schema) only see rules with allowed prefixes. By default, only SEC- (security) and REL- (reliability) rules pass through. Schema files also see COMP- (compliance) rules.

This means performance, cost, quality, and compliance noise is eliminated entirely in non-production files.

### Layer 2: Deny List

Even within allowed prefixes, specific rules produce false positives in certain contexts. The deny list removes these:

| Context | Denied Rules | Reason |
|---------|-------------|--------|
| migration | SEC-INJ-005 | Migration data is developer-controlled, not user input |
| seed | SEC-INJ-005 | Seed data is developer-controlled, not user input |
| test | REL-FK-002, REL-DEAD-002, SEC-AUTHZ-003 | Test cleanup is intentional; no tenant scoping needed |
| application | QUAL-DBT-001, QUAL-DBT-002 | Not a dbt project |
| adhoc | QUAL-DBT-001, QUAL-DBT-002 | Not a dbt project |
| dbt_model | PERF-SCAN-003 | dbt models do not use LIMIT |

### Layer 3: Cross-File Filtering

Cross-file rules (like unused object detection QUAL-DEAD-001) run after per-file analysis. SlowQL applies the same context filtering to cross-file issues based on the source file that produced them, preventing bypass.

## Classification Logic

Files are classified in priority order:

1. **Path patterns** (highest confidence) - directory structure and filename matching
2. **Content heuristics** - CREATE OR REPLACE VIEW, CREATE PROCEDURE, etc.
3. **Default** - adhoc for raw SQL strings with no file path

### Path Pattern Priority

More specific patterns match first. For example:
- models/test.sql -> dbt_model (directory match, not filename match)
- tests/test.sql -> test (directory match)
- mytest.sql -> test (filename match)

### Filename Matching

The test filename pattern (*test*.sql) only matches within a single path component. This prevents false matches on pytest temporary directories like pytest-9/test_analyze_file0/query.sql.

## Example Output

    migrations/001_create_users.sql  -> migration  -> 1 issue  (REL-IDEM-001)
    tests/test_queries.sql           -> test       -> 0 issues (clean)
    seeds/sample_data.sql            -> seed       -> 1 issue  (REL-IDEM-001)
    models/users_recent.sql          -> dbt_model  -> 4 issues (performance + quality)
    src/db/queries.sql               -> adhoc      -> 7 issues (full analysis)
    schema.sql                       -> ddl_schema -> 1 issue  (COMP-RET-001)

## When Context Is Not Enough

If a rule fires correctly but is contextually inapplicable to a specific line, use [inline suppression](../usage/suppression.md) as a last resort. Context-aware filtering handles the broad patterns; suppression handles the edge cases.

## API Reference

    from slowql.core.context import classify_source, filter_issues_by_context

    # Classify a file
    context = classify_source("migrations/001_create_users.sql")
    # -> "migration"

    # Classify raw SQL (no file)
    context = classify_source(None, "SELECT * FROM users")
    # -> "adhoc"

    # Filter issues by context
    filtered = filter_issues_by_context(issues, "migration")
