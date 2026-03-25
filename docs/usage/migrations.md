# Migration Analysis

SlowQL provides native support for popular database migration frameworks. Instead of analyzing migration files as isolated SQL snippets, SlowQL understands the context, ordering, and dependencies of your migration project.

## Supported Frameworks

SlowQL automatically detects the following migration frameworks:

- **Alembic** (Python/SQLAlchemy)
- **Django Migrations**
- **Flyway** (Java/JVM)
- **Liquibase** (Java/JVM)
- **Prisma Migrate** (TypeScript/Node.js)
- **Knex** (JavaScript/TypeScript)

## How it Works

When you point SlowQL to a directory, it first checks if it contains a known migration project structure. If a framework is detected:

1. **Project Detection:** SlowQL identifies the framework (e.g., finding `alembic.ini` or `versions/` folder).
2. **Migration Discovery:** It discovers all migration files and determines their execution order based on timestamps or dependencies.
3. **State Tracking:** SlowQL simulates the application of migrations to track the evolving schema state.
4. **Contextual Analysis:** It analyzes each migration with the knowledge of what the schema looked like *before* and *after* that migration.

## Command Usage

Simply pass the directory containing your migration project:

```bash
# Analyze all migrations in the current project
slowql ./migrations

# Analyze specific migration files with project context
slowql ./migrations/versions/v1_init.py --input-file ./migrations/versions/v2_add_col.py
```

## Migration Rules

SlowQL includes specific rules for migrations, such as:

- **Destructive Changes:** Detecting `DROP COLUMN` or `RENAME TABLE` that might break existing queries.
- **Locking Issues:** Identifying DDL operations that perform full table locks on large tables.
- **Idempotency:** Ensuring migrations can be safely run multiple times without error.
- **Dialect Compatibility:** Verifying that migration SQL is valid for your target database dialect.

## Configuration

You can configure migration analysis in your `slowql.toml`:

```toml
[analysis]
# Focus analysis on specific migration folders
migration_dirs = ["./backend/migrations"]

# Enable destructive change detection
detect_destructive_changes = true

# Require review for any DDL on production tables
critical_production_tables = ["users", "orders", "payments"]
```
