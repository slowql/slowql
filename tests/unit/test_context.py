# tests/unit/test_context.py
"""
Tests for source context classification and filtering.
"""

from __future__ import annotations

from slowql.core.context import (
    ADHOC,
    APPLICATION,
    DBT_MODEL,
    DDL_SCHEMA,
    MIGRATION,
    SEED,
    TEST,
    classify_source,
    filter_issues_by_context,
)
from slowql.core.models import (
    Dimension,
    Issue,
    Location,
    Severity,
)

# ---------------------------------------------------------------------------
# classify_source - path-based
# ---------------------------------------------------------------------------


class TestClassifySourcePath:
    """Path-based source context classification."""

    def test_alembic_versions_dir(self) -> None:
        assert classify_source("alembic/versions/001_init.py") == MIGRATION

    def test_alembic_root_dir(self) -> None:
        assert classify_source("alembic/env.py") == MIGRATION

    def test_migrations_dir(self) -> None:
        assert classify_source("migrations/001_create_users.py") == MIGRATION

    def test_migration_singular(self) -> None:
        assert classify_source("migration/001.sql") == MIGRATION

    def test_db_migrate(self) -> None:
        assert classify_source("db/migrate/20240101_create_users.rb") == MIGRATION

    def test_db_migrations(self) -> None:
        assert classify_source("db/migrations/001.sql") == MIGRATION

    def test_flyway_dir(self) -> None:
        assert classify_source("flyway/V001__init.sql") == MIGRATION

    def test_liquibase_dir(self) -> None:
        assert classify_source("liquibase/changelog-001.xml") == MIGRATION

    def test_prisma_migrations(self) -> None:
        assert classify_source("prisma/migrations/001_init/migration.sql") == MIGRATION

    def test_spring_boot_migration(self) -> None:
        assert classify_source("src/main/resources/db/migration/V001__init.sql") == MIGRATION

    def test_tests_dir(self) -> None:
        assert classify_source("tests/test_queries.sql") == TEST

    def test_test_singular(self) -> None:
        assert classify_source("test/queries.sql") == TEST

    def test_spec_dir(self) -> None:
        assert classify_source("spec/query_spec.sql") == TEST

    def test_dunder_tests(self) -> None:
        assert classify_source("__tests__/queries.sql") == TEST

    def test_test_filename(self) -> None:
        assert classify_source("mytest.sql") == TEST

    def test_seeds_dir(self) -> None:
        assert classify_source("seeds/users.sql") == SEED

    def test_seed_singular(self) -> None:
        assert classify_source("seed/data.sql") == SEED

    def test_fixtures_dir(self) -> None:
        assert classify_source("fixtures/sample_data.sql") == SEED

    def test_fixture_singular(self) -> None:
        assert classify_source("fixture/data.sql") == SEED

    def test_schema_sql_file(self) -> None:
        assert classify_source("schema.sql") == DDL_SCHEMA

    def test_schema_dir(self) -> None:
        assert classify_source("schema/tables.sql") == DDL_SCHEMA

    def test_ddl_dir(self) -> None:
        assert classify_source("ddl/create_tables.sql") == DDL_SCHEMA

    def test_models_dir(self) -> None:
        assert classify_source("models/users.sql") == DBT_MODEL

    def test_dbt_models_dir(self) -> None:
        assert classify_source("dbt_models/users.sql") == DBT_MODEL

    def test_python_file(self) -> None:
        assert classify_source("src/app.py") == APPLICATION

    def test_typescript_file(self) -> None:
        assert classify_source("src/service.ts") == APPLICATION

    def test_javascript_file(self) -> None:
        assert classify_source("src/service.js") == APPLICATION

    def test_java_file(self) -> None:
        assert classify_source("src/Main.java") == APPLICATION

    def test_go_file(self) -> None:
        assert classify_source("internal/db/queries.go") == APPLICATION

    def test_ruby_file(self) -> None:
        assert classify_source("app/models/user.rb") == APPLICATION

    def test_xml_file(self) -> None:
        assert classify_source("mapper/UserMapper.xml") == APPLICATION

    def test_standalone_sql(self) -> None:
        assert classify_source("queries.sql") == ADHOC

    def test_none_path_no_content(self) -> None:
        assert classify_source(None) == ADHOC

    def test_none_path_with_plain_content(self) -> None:
        assert classify_source(None, "SELECT 1") == ADHOC

    def test_windows_path_separator(self) -> None:
        assert classify_source("migrations\\001_init.sql") == MIGRATION


# ---------------------------------------------------------------------------
# classify_source - content-based
# ---------------------------------------------------------------------------


class TestClassifySourceContent:
    """Content-based source context classification."""

    def test_alembic_revision_content(self) -> None:
        content = "revision = \'abc123\'\ndown_revision = None"
        assert classify_source(None, content) == MIGRATION

    def test_django_migration_class(self) -> None:
        content = "class CreateUsersMigration(Migration):\n    pass"
        assert classify_source(None, content) == MIGRATION

    def test_up_down_functions(self) -> None:
        content = "def up(connection):\n    pass"
        assert classify_source(None, content) == MIGRATION

    def test_flyway_comment(self) -> None:
        content = "-- flyway migration\nSELECT 1"
        assert classify_source(None, content) == MIGRATION

    def test_migrate_comment_up(self) -> None:
        content = "-- migrate:up\nSELECT 1"
        assert classify_source(None, content) == MIGRATION

    def test_migrate_comment_down(self) -> None:
        content = "-- migrate:down\nSELECT 1"
        assert classify_source(None, content) == MIGRATION

    def test_dbt_ref(self) -> None:
        content = "SELECT * FROM {{ ref(\'users\') }}"
        assert classify_source(None, content) == DBT_MODEL

    def test_dbt_config(self) -> None:
        content = "{% config(materialized=\'table\') %}\nSELECT 1"
        assert classify_source(None, content) == DBT_MODEL

    def test_plain_sql_no_markers(self) -> None:
        content = "SELECT id, name FROM users WHERE id = 1"
        assert classify_source(None, content) == ADHOC

    def test_empty_content(self) -> None:
        assert classify_source(None, "") == ADHOC


# ---------------------------------------------------------------------------
# classify_source - path takes priority over content
# ---------------------------------------------------------------------------


class TestClassifySourcePriority:
    """Path-based detection should take priority over content."""

    def test_migration_dir_overrides_plain_content(self) -> None:
        content = "SELECT * FROM users"
        assert classify_source("migrations/001_init.sql", content) == MIGRATION

    def test_tests_dir_takes_priority(self) -> None:
        content = "revision = \'abc\'\ndown_revision = None"
        assert classify_source("tests/test_migration.py", content) == TEST


# ---------------------------------------------------------------------------
# filter_issues_by_context
# ---------------------------------------------------------------------------


def _make_issue(rule_id: str) -> Issue:
    """Helper to create a minimal issue for testing."""
    return Issue(
        rule_id=rule_id,
        message=f"Issue from {rule_id}",
        severity=Severity.MEDIUM,
        dimension=Dimension.PERFORMANCE,
        location=Location(line=1, column=1),
        snippet="SELECT * FROM users",
    )


class TestFilterIssuesByContext:
    """Context-based issue filtering."""

    def test_adhoc_no_filtering(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        assert filter_issues_by_context(issues, ADHOC) == issues

    def test_application_no_filtering(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        assert filter_issues_by_context(issues, APPLICATION) == issues

    def test_empty_string_no_filtering(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        assert filter_issues_by_context(issues, "") == issues

    def test_migration_suppresses_select_star(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        result = filter_issues_by_context(issues, MIGRATION)
        assert result == []

    def test_migration_suppresses_missing_where(self) -> None:
        issues = [_make_issue("PERF-SCAN-002")]
        result = filter_issues_by_context(issues, MIGRATION)
        assert result == []

    def test_migration_suppresses_index_rules_by_prefix(self) -> None:
        issues = [
            _make_issue("PERF-IDX-001"),
            _make_issue("PERF-IDX-005"),
            _make_issue("PERF-IDX-009"),
        ]
        result = filter_issues_by_context(issues, MIGRATION)
        assert result == []

    def test_migration_suppresses_schema_idx_by_prefix(self) -> None:
        issues = [_make_issue("SCHEMA-IDX-001")]
        result = filter_issues_by_context(issues, MIGRATION)
        assert result == []

    def test_migration_keeps_security_issues(self) -> None:
        issues = [_make_issue("SEC-INJ-001")]
        result = filter_issues_by_context(issues, MIGRATION)
        assert len(result) == 1
        assert result[0].rule_id == "SEC-INJ-001"

    def test_migration_keeps_reliability_issues(self) -> None:
        issues = [_make_issue("REL-DATA-001")]
        result = filter_issues_by_context(issues, MIGRATION)
        assert len(result) == 1
        assert result[0].rule_id == "REL-DATA-001"

    def test_test_suppresses_select_star(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        result = filter_issues_by_context(issues, TEST)
        assert result == []

    def test_test_suppresses_index_rules(self) -> None:
        issues = [_make_issue("PERF-IDX-003")]
        result = filter_issues_by_context(issues, TEST)
        assert result == []

    def test_test_keeps_security_issues(self) -> None:
        issues = [_make_issue("SEC-INJ-001")]
        result = filter_issues_by_context(issues, TEST)
        assert len(result) == 1

    def test_seed_suppresses_select_star(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        result = filter_issues_by_context(issues, SEED)
        assert result == []

    def test_ddl_suppresses_select_star(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        result = filter_issues_by_context(issues, DDL_SCHEMA)
        assert result == []

    def test_mixed_issues_partial_filter(self) -> None:
        issues = [
            _make_issue("PERF-SCAN-001"),
            _make_issue("SEC-INJ-001"),
            _make_issue("PERF-SCAN-002"),
            _make_issue("REL-DATA-001"),
        ]
        result = filter_issues_by_context(issues, MIGRATION)
        rule_ids = [i.rule_id for i in result]
        assert "SEC-INJ-001" in rule_ids
        assert "REL-DATA-001" in rule_ids
        assert "PERF-SCAN-001" not in rule_ids
        assert "PERF-SCAN-002" not in rule_ids

    def test_empty_issues_list(self) -> None:
        result = filter_issues_by_context([], MIGRATION)
        assert result == []

    def test_unknown_context_no_filtering(self) -> None:
        issues = [_make_issue("PERF-SCAN-001")]
        result = filter_issues_by_context(issues, "unknown_context")
        assert result == issues


class TestEngineContextIntegration:
    """Integration: engine + context.

    Verify that the engine tags queries and filters correctly.
    """

    def test_analyze_tags_adhoc_by_default(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze("SELECT * FROM users")
        assert len(result.queries) > 0
        assert result.queries[0].source_context == ADHOC

    def test_analyze_tags_migration_from_path(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="migrations/001_init.sql"
        )
        assert len(result.queries) > 0
        assert result.queries[0].source_context == MIGRATION

    def test_analyze_tags_test_from_path(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="tests/test_queries.sql"
        )
        assert len(result.queries) > 0
        assert result.queries[0].source_context == TEST

    def test_analyze_tags_application_from_path(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="src/app.py"
        )
        assert len(result.queries) > 0
        assert result.queries[0].source_context == APPLICATION

    def test_migration_no_select_star_false_positive(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="migrations/001_init.sql"
        )
        rule_ids = [i.rule_id for i in result.issues]
        assert "PERF-SCAN-001" not in rule_ids

    def test_adhoc_flags_select_star(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze("SELECT * FROM users")
        rule_ids = [i.rule_id for i in result.issues]
        assert "PERF-SCAN-001" in rule_ids

    def test_application_flags_select_star(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="src/app.py"
        )
        rule_ids = [i.rule_id for i in result.issues]
        assert "PERF-SCAN-001" in rule_ids

    def test_test_no_select_star_false_positive(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="tests/test_queries.sql"
        )
        rule_ids = [i.rule_id for i in result.issues]
        assert "PERF-SCAN-001" not in rule_ids

    def test_seed_no_select_star_false_positive(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="seeds/users.sql"
        )
        rule_ids = [i.rule_id for i in result.issues]
        assert "PERF-SCAN-001" not in rule_ids

    def test_migration_keeps_security_issues(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users WHERE name = \'\' OR 1=1 --",
            file_path="migrations/001_init.sql",
        )
        # Security rules should still fire in migrations
        # Performance rules should be filtered
        perf_rules = [i.rule_id for i in result.issues if i.dimension == Dimension.PERFORMANCE]
        assert "PERF-SCAN-001" not in perf_rules

    def test_to_dict_includes_source_context(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users", file_path="migrations/001_init.sql"
        )
        d = result.queries[0].to_dict()
        assert d["source_context"] == MIGRATION
