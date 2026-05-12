"""
End-to-end precision test: every issue SlowQL flags must be a true positive.

Creates a temporary repo with files across all contexts, runs full analysis,
and verifies each issue against an explicit expected set.
"""
import os
import pytest
from slowql.core.engine import SlowQL
from slowql.core.context import classify_source


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    """Create a realistic multi-context project."""
    base = tmp_path_factory.mktemp("repo")

    # Migration
    mig = base / "migrations"
    mig.mkdir()
    (mig / "001_create_users.sql").write_text(
        "CREATE TABLE users (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    email VARCHAR(255) NOT NULL UNIQUE,\n"
        "    password_hash VARCHAR(255) NOT NULL\n"
        ");\n"
        "INSERT INTO users (email, password_hash) VALUES ('admin@test.com', 'hashed');\n"
    )
    (mig / "002_add_orders.sql").write_text(
        "CREATE TABLE orders (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    user_id INTEGER REFERENCES users(id),\n"
        "    total DECIMAL(10,2) NOT NULL\n"
        ");\n"
    )

    # Test
    tst = base / "tests"
    tst.mkdir()
    (tst / "test_queries.sql").write_text(
        "SELECT * FROM users WHERE email = 'test@test.com';\n"
        "DELETE FROM users WHERE email = 'test@test.com';\n"
        "SELECT COUNT(*) FROM orders;\n"
        "SELECT * FROM orders WHERE status = 'pending';\n"
    )
    (tst / "test_reports.sql").write_text(
        "SELECT u.name, COUNT(o.id) as cnt\n"
        "FROM users u LEFT JOIN orders o ON o.user_id = u.id\n"
        "GROUP BY u.name HAVING COUNT(o.id) > 0;\n"
    )

    # Seed
    seed = base / "seeds"
    seed.mkdir()
    (seed / "sample_data.sql").write_text(
        "INSERT INTO users (email, password_hash) VALUES\n"
        "  ('alice@test.com', 'h1'), ('bob@test.com', 'h2');\n"
        "INSERT INTO orders (user_id, total, status) VALUES\n"
        "  (1, 99.99, 'completed'), (2, 49.50, 'pending');\n"
    )

    # dbt model
    models = base / "models"
    models.mkdir()
    (models / "users_recent.sql").write_text(
        "SELECT * FROM {{ ref('users') }} WHERE created_at > '2024-01-01'\n"
    )
    (models / "orders_summary.sql").write_text(
        "SELECT u.email, COUNT(o.id) as cnt, SUM(o.total) as spent\n"
        "FROM {{ ref('users') }} u\n"
        "LEFT JOIN {{ ref('orders') }} o ON o.user_id = u.id\n"
        "GROUP BY u.email\n"
    )

    # Application
    app = base / "src" / "db"
    app.mkdir(parents=True)
    (app / "queries.sql").write_text(
        "SELECT * FROM users\n"
        "LEFT JOIN orders ON orders.user_id = users.id\n"
        "WHERE users.created_at > '2024-01-01'\n"
        "ORDER BY users.name;\n"
        "SELECT email, name FROM users WHERE email = ?;\n"
    )

    # DDL Schema
    (base / "schema.sql").write_text(
        "CREATE TABLE audit_log (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    table_name VARCHAR(100) NOT NULL,\n"
        "    action VARCHAR(20) NOT NULL,\n"
        "    performed_at TIMESTAMP DEFAULT NOW()\n"
        ");\n"
    )

    # Adhoc file (unrecognized path)
    scripts = base / "scripts"
    scripts.mkdir()
    (scripts / "cleanup.sql").write_text(
        "DELETE FROM orders WHERE created_at < '2023-01-01';\n"
    )

    return {
        "base": base,
        "files": {
            "migration": str(mig / "001_create_users.sql"),
            "migration_ddl_only": str(mig / "002_add_orders.sql"),
            "test": str(tst / "test_queries.sql"),
            "test_reports": str(tst / "test_reports.sql"),
            "seed": str(seed / "sample_data.sql"),
            "dbt_simple": str(models / "users_recent.sql"),
            "dbt_join": str(models / "orders_summary.sql"),
            "application": str(app / "queries.sql"),
            "ddl_schema": str(base / "schema.sql"),
            "adhoc_file": str(scripts / "cleanup.sql"),
        },
    }


CLASSIFICATION_EXPECTED = {
    "migration": "migration",
    "migration_ddl_only": "migration",
    "test": "test",
    "test_reports": "test",
    "seed": "seed",
    "dbt_simple": "dbt_model",
    "dbt_join": "dbt_model",
    "application": "application",
    "ddl_schema": "ddl_schema",
    "adhoc_file": "adhoc",
}


class TestContextClassification:
    @pytest.mark.parametrize("key", sorted(CLASSIFICATION_EXPECTED))
    def test_file_classifies_correctly(self, repo, key):
        path = repo["files"][key]
        expected = CLASSIFICATION_EXPECTED[key]
        got = classify_source(path)
        assert got == expected, f"{path}: expected {expected}, got {got}"

    def test_none_classifies_as_adhoc(self):
        assert classify_source(None) == "adhoc"

    def test_none_with_content_classifies_as_adhoc(self):
        assert classify_source(None, "SELECT * FROM users") == "adhoc"

    def test_models_test_sql_classifies_as_dbt(self):
        assert classify_source("models/test.sql") == "dbt_model"

    def test_tests_test_sql_classifies_as_test(self):
        assert classify_source("tests/test.sql") == "test"

    def test_mytest_sql_classifies_as_test(self):
        assert classify_source("mytest.sql") == "test"

    def test_java_migration_still_migration(self):
        assert classify_source("src/main/resources/db/migration/v1.sql") == "migration"

    def test_alembic_classifies_as_migration(self):
        assert classify_source("alembic/versions/abc123.py") == "migration"


FORBIDDEN_RULES = {
    "migration": [
        "PERF-SCAN-001", "PERF-SCAN-003", "QUAL-DBT-001", "QUAL-DBT-002",
        "SEC-INJ-005", "COMP-GDPR-001", "COMP-GDPR-006",
    ],
    "test": [
        "PERF-SCAN-001", "PERF-SCAN-003", "QUAL-DBT-001",
        "SEC-INJ-005", "SEC-AUTHZ-003", "REL-FK-002", "REL-DEAD-002",
    ],
    "seed": [
        "PERF-SCAN-001", "QUAL-DBT-001", "SEC-INJ-005",
    ],
    "ddl_schema": [
        "PERF-SCAN-001", "QUAL-DBT-001", "SEC-INJ-005",
    ],
    "dbt_simple": [
        "QUAL-DBT-001", "QUAL-DBT-002", "PERF-SCAN-003",
    ],
    "dbt_join": [
        "QUAL-DBT-001", "QUAL-DBT-002", "PERF-SCAN-003",
    ],
    "application": [
        "QUAL-DBT-001", "QUAL-DBT-002",
    ],
    "adhoc_file": [
        "QUAL-DBT-001", "QUAL-DBT-002",
    ],
}


class TestFalsePositiveExclusion:
    @pytest.mark.parametrize("key", sorted(FORBIDDEN_RULES))
    def test_no_forbidden_rules_in_context(self, repo, key):
        path = repo["files"][key]
        engine = SlowQL()
        result = engine.analyze_file(path)
        rule_ids = {issue.rule_id for issue in result.issues}
        forbidden = set(FORBIDDEN_RULES[key])
        violations = rule_ids & forbidden
        assert not violations, (
            f"{os.path.basename(path)} (ctx={key}): found forbidden rules {violations}"
        )

    def test_adhoc_no_dbt_rules(self):
        engine = SlowQL()
        result = engine.analyze(
            "SELECT * FROM users LEFT JOIN orders ON orders.user_id = users.id "
            "WHERE users.created_at > '2024-01-01';"
        )
        rule_ids = {issue.rule_id for issue in result.issues}
        assert "QUAL-DBT-001" not in rule_ids
        assert "QUAL-DBT-002" not in rule_ids


REQUIRED_RULES = {
    "migration": ["REL-IDEM-001"],
    "seed": ["REL-IDEM-001"],
    "dbt_simple": ["PERF-SCAN-001"],
    "application": ["PERF-SCAN-001"],
    "ddl_schema": ["COMP-RET-001"],
}


class TestTruePositivePresence:
    @pytest.mark.parametrize("key", sorted(REQUIRED_RULES))
    def test_required_rules_fire(self, repo, key):
        path = repo["files"][key]
        engine = SlowQL()
        result = engine.analyze_file(path)
        rule_ids = {issue.rule_id for issue in result.issues}
        required = set(REQUIRED_RULES[key])
        missing = required - rule_ids
        assert not missing, (
            f"{os.path.basename(path)} (ctx={key}): missing required rules {missing}"
        )


ZERO_ISSUE_FILES = ["migration_ddl_only", "test", "test_reports"]


class TestZeroIssues:
    @pytest.mark.parametrize("key", ZERO_ISSUE_FILES)
    def test_zero_issues(self, repo, key):
        path = repo["files"][key]
        engine = SlowQL()
        result = engine.analyze_file(path)
        assert len(result.issues) == 0, (
            f"{os.path.basename(path)} (ctx={key}): "
            f"expected 0 issues, got {[i.rule_id for i in result.issues]}"
        )


EXPECTED_ISSUES = {
    "migration": {"REL-IDEM-001": 1},
    "migration_ddl_only": {},
    "test": {},
    "test_reports": {},
    "seed": {"REL-IDEM-001": 1, "REL-FK-001": 1},
    "dbt_simple": {"PERF-SCAN-001": 1, "PERF-IDX-006": 1, "QUAL-MODERN-002": 1},
    "dbt_join": {
        "PERF-AGG-001": 1, "COMP-GDPR-001": 1, "QUAL-NAME-002": 1,
        "PERF-MEM-004": 1, "COST-COMP-002": 1,
    },
    "application": {
        "SEC-AUTHZ-003": 1, "PERF-SCAN-001": 1,
        "PERF-SCAN-003": 1, "QUAL-MODERN-002": 1,
        "COMP-GDPR-001": 1, "COMP-GDPR-006": 1,
        "PERF-IDX-006": 1, "COST-IDX-003": 1,
    },
    "ddl_schema": {"COMP-RET-001": 1},
    "adhoc_file": {
        "QUAL-MODERN-002": 1, "REL-FK-002": 1,
        "REL-DEAD-002": 1, "PERF-BATCH-001": 1,
    },
}


class TestFullPrecisionAudit:
    @pytest.mark.parametrize("key", sorted(EXPECTED_ISSUES))
    def test_all_issues_accounted(self, repo, key):
        path = repo["files"][key]
        engine = SlowQL()
        result = engine.analyze_file(path)
        expected = EXPECTED_ISSUES[key]

        rule_counts = {}
        for issue in result.issues:
            rule_counts[issue.rule_id] = rule_counts.get(issue.rule_id, 0) + 1

        unexpected = set(rule_counts) - set(expected)
        assert not unexpected, (
            f"{os.path.basename(path)} (ctx={key}): unexpected rules {unexpected}"
        )

        for rule_id, min_count in expected.items():
            actual = rule_counts.get(rule_id, 0)
            assert actual >= min_count, (
                f"{os.path.basename(path)} (ctx={key}): "
                f"expected >={min_count} {rule_id}, got {actual}"
            )


class TestEdgeCaseClassification:
    """Ambiguous and nested paths must classify correctly."""

    def test_src_migrations_classifies_as_migration(self):
        # migration pattern is more specific than src/
        assert classify_source("src/migrations/001.sql") == "migration"

    def test_src_tests_classifies_as_test(self):
        # test pattern is more specific than src/
        assert classify_source("src/tests/test_foo.sql") == "test"

    def test_src_seeds_classifies_as_seed(self):
        assert classify_source("src/seeds/data.sql") == "seed"

    def test_src_models_classifies_as_dbt(self):
        assert classify_source("src/models/users.sql") == "dbt_model"

    def test_tests_models_classifies_as_test(self):
        # tests/ is a directory match, models/ is filename match
        assert classify_source("tests/models/foo.sql") == "test"

    def test_pytest_tmpdir_not_test(self):
        # pytest-9/test_analyze_file0/query.sql should NOT be test
        assert classify_source("pytest-9/test_analyze_file0/query.sql") == "adhoc"

    def test_deeply_nested_migration(self):
        assert classify_source("/home/user/project/db/migrate/2024/01/001.sql") == "migration"

    def test_alembic_versions_nested(self):
        assert classify_source("/opt/app/alembic/versions/abc123_migration.py") == "migration"


class TestContentHeuristics:
    """Content-based classification for views and stored procs."""

    def test_create_view_content(self):
        assert classify_source(None, "CREATE OR REPLACE VIEW v AS SELECT 1") == "view_definition"

    def test_create_procedure_content(self):
        assert classify_source(None, "CREATE PROCEDURE foo() BEGIN SELECT 1; END") == "stored_procedure"

    def test_create_function_content(self):
        assert classify_source(None, "CREATE FUNCTION foo() RETURNS INT BEGIN RETURN 1; END") == "stored_procedure"

    def test_regular_sql_stays_adhoc(self):
        assert classify_source(None, "SELECT * FROM users") == "adhoc"

    def test_path_overrides_content(self):
        # Even with CREATE VIEW, path-based test pattern wins
        assert classify_source("tests/test_views.sql", "CREATE OR REPLACE VIEW v AS SELECT 1") == "test"


class TestCrossFileContextFiltering:
    """Cross-file issues must respect per-file context."""

    def test_cross_file_filter_function_exists(self):
        from slowql.core.context import filter_issues_by_context
        assert callable(filter_issues_by_context)

    def test_migration_issues_filtered(self):
        from slowql.core.context import filter_issues_by_context
        from slowql.core.models import Issue, Severity, Location
        issues = [
            Issue(rule_id="REL-IDEM-001", severity=Severity.HIGH, message="test",
                  dimension="reliability", location=Location(file="migrations/001.sql", line=1, column=1), snippet="INSERT INTO users"),
            Issue(rule_id="PERF-SCAN-001", severity=Severity.MEDIUM, message="test",
                  dimension="performance", location=Location(file="migrations/001.sql", line=1, column=1), snippet="SELECT * FROM users"),
        ]
        filtered = filter_issues_by_context(issues, "migration")
        rule_ids = {i.rule_id for i in filtered}
        assert "REL-IDEM-001" in rule_ids
        assert "PERF-SCAN-001" not in rule_ids

    def test_test_issues_filtered(self):
        from slowql.core.context import filter_issues_by_context
        from slowql.core.models import Issue, Severity, Location
        issues = [
            Issue(rule_id="SEC-AUTHZ-003", severity=Severity.HIGH, message="test",
                  dimension="security", location=Location(file="tests/test.sql", line=1, column=1), snippet="SELECT * FROM users"),
            Issue(rule_id="SEC-INJ-001", severity=Severity.HIGH, message="test",
                  dimension="security", location=Location(file="tests/test.sql", line=1, column=1), snippet="SELECT * FROM users"),
        ]
        filtered = filter_issues_by_context(issues, "test")
        rule_ids = {i.rule_id for i in filtered}
        assert "SEC-AUTHZ-003" not in rule_ids  # denied for test
        assert "SEC-INJ-001" in rule_ids  # allowed
