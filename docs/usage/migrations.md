# Migration Analysis

SlowQL automatically detects and classifies migration files. When a file is classified as a migration, only security and reliability rules fire. Performance, cost, quality, and compliance rules are suppressed.

## Supported Frameworks

SlowQL detects migrations by file path patterns:

| Framework | Detected Paths |
|-----------|---------------|
| Alembic | `/alembic/`, `/versions/` |
| Django | `/migrations/` |
| Flyway | `/flyway/`, `*.sql` in migration dirs |
| Liquibase | `/liquibase/` |
| Prisma | `/prisma/migrations/` |
| Knex | `/migrations/` |
| Generic | `/db/migrate/`, `/migrator/`, `/snapshot/` |

## Context Rules for Migrations

In migration context, only these rule prefixes are allowed:
- `SEC-` (security)
- `REL-` (reliability)

Specific rules are additionally denied even in migration context:
- `SEC-INJ-005` (second-order injection) - migration data is developer-controlled
- `REL-DATA-004` (DROP statement) - intentional in migrations
- `MIG-BRK-001` (breaking change) - not cross-file in migration directories

## Migration-Specific Rules

| Rule | Description |
|------|-------------|
| `MIG-BRK-001` | Breaking change: dropping table that is referenced in another file |
| `SCH-BRK-001` | Cross-file breaking change: dropped column referenced elsewhere |

## Usage

```bash
# Analyze all migrations
slowql db/migrations/

# Analyze with schema validation
slowql db/migrations/ --schema db/schema.sql

# Include migration context in output (migrations are nonprod by default)
slowql db/migrations/ --include-nonprod
```

## Why Migrations Are Non-Production

By default, migrations are classified as non-production and suppressed from the main output. This is intentional:

* Migrations routinely use `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`
* These are intentional destructive operations, not bugs
* Performance rules on `SELECT *` or missing `LIMIT` are irrelevant in migration context

Use `--include-nonprod` to see migration findings alongside application findings.