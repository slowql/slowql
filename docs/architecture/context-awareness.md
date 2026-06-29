# Context Awareness

SlowQL automatically classifies every file by its role in the project. This classification determines which rules are applied.

## Context Types

| Context | Description | Allowed Rule Prefixes |
|---------|-------------|----------------------|
| `application` | Production application code | All rules |
| `migration` | Database migration files | SEC-, REL- (minus deny list) |
| `test` | Test files and test data | SEC-, REL- (minus deny list) |
| `seed` | Seed and fixture data | SEC-, REL- |
| `example` | Examples, docs, demos, scripts | SEC-, REL- |
| `framework_internal` | ORM/framework SQL adapters | SEC-, REL- (minus deny list) |
| `ddl_schema` | Schema definition files | SEC-, REL-, COMP- |
| `dbt_model` | dbt model files | All rules (minus PERF-SCAN-003) |
| `adhoc` | Stdin or unclassified | All rules (minus dbt rules) |

## Path-Based Classification

Context is determined by matching file paths against patterns, checked in order:

- `/migrations/`, `/db/migrate/`, `/alembic/` -> migration
- `/tests/`, `/spec/`, `/__tests__/`, `_test.go` -> test
- `/testdata/`, `/endtoend/`, `/golden/` -> test
- `/integration-tests/`, `/roachtest/` -> test
- `/ci/`, `_fuzz` -> test
- `/seeds/`, `/fixtures/` -> seed
- `/examples/`, `/docs/`, `/demo/`, `/scripts/` -> example
- `/bench/`, `/benchmarks/`, `/dataset_templates/` -> example
- `/dev/` -> example
- `/config/` -> ddl_schema
- `/schema/`, `/ddl/` -> ddl_schema
- `/connection_adapters/`, `/db/backends/` -> framework_internal
- `/driver-adapters/`, `/src-rsr/` -> framework_internal
- `/information_schema/`, `/columnar/sql/` -> framework_internal
- `/src/backend/` -> framework_internal
- `/src/site/` -> example
- `/data/procs/`, `/vulnserver/` -> example
- `/src/` -> application

## Content-Based Classification

If path matching does not determine context, file content is checked:
- dbt `{{ ref() }}` patterns -> dbt_model
- Migration class definitions -> migration

## Non-Production Suppression

By default, non-production issues are suppressed in directory scans. Use `--include-nonprod` to see all findings regardless of context.

The suppressed count is always shown so users know additional findings exist:
``` text
No issues found.
(71147 issues available with --min-confidence contextual or --include-nonprod)
```
