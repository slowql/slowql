"""File-based rule trigger tests for context-dependent rules."""
from pathlib import Path
import pytest
from slowql.core.engine import SlowQL


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    """Create a temporary project with files for different contexts."""
    base = tmp_path_factory.mktemp("repo")

    # Migration context
    mig = base / "migrations"
    mig.mkdir()
    (mig / "001_drop_table.sql").write_text("DROP TABLE users;\n")

    # dbt models
    models = base / "models"
    models.mkdir()
    (models / "hardcoded_table.sql").write_text("SELECT * FROM users;\n")
    (models / "hardcoded_schema.sql").write_text("SELECT * FROM raw.users;\n")

    # Multi-statement files
    ms = base / "multistmt"
    ms.mkdir()
    (ms / "long_transaction.sql").write_text(
        "BEGIN;\nSAVEPOINT sp1;\nINSERT INTO t1 VALUES (1);\nINSERT INTO t1 VALUES (2);\nINSERT INTO t1 VALUES (3);\nCOMMIT;\n"
    )
    (ms / "dead_code.sql").write_text(
        "CREATE PROCEDURE p() BEGIN RETURN 1; SELECT * FROM users; END;\n"
    )

    # Schema file for schema-aware tests
    (base / "schema.sql").write_text(
        "CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR);\n"
    )

    # ClickHouse test files
    ch = base / "clickhouse"
    ch.mkdir()
    (ch / "join_subquery.sql").write_text(
        "SELECT * FROM users JOIN (SELECT * FROM orders) AS o ON users.id = o.id;\n"
    )
    (ch / "replace_merge.sql").write_text(
        "SELECT * FROM users -- REPLACING\n"
    )

    return base


class TestDbtContext:
    def test_hardcoded_table(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(str(repo / "models" / "hardcoded_table.sql"))
        assert "QUAL-DBT-001" in {i.rule_id for i in result.issues}

    def test_hardcoded_schema(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(str(repo / "models" / "hardcoded_schema.sql"))
        assert "QUAL-DBT-002" in {i.rule_id for i in result.issues}


class TestMultiStatement:
    def test_long_transaction_savepoint(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(str(repo / "multistmt" / "long_transaction.sql"))
        assert "REL-REC-001" in {i.rule_id for i in result.issues}

    def test_dead_code_after_return(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(str(repo / "multistmt" / "dead_code.sql"))
        assert "QUAL-DEAD-002" in {i.rule_id for i in result.issues}


class TestClickHouseDialect:
    def test_join_without_global(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(
            str(repo / "clickhouse" / "join_subquery.sql"), dialect="clickhouse"
        )
        assert "PERF-CH-002" in {i.rule_id for i in result.issues}

    def test_select_without_final(self, repo):
        engine = SlowQL()
        result = engine.analyze_file(
            str(repo / "clickhouse" / "replace_merge.sql"), dialect="clickhouse"
        )
        assert "REL-CH-001" in {i.rule_id for i in result.issues}


class TestSchemaAware:
    def test_missing_table(self, repo):
        engine = SlowQL(schema_path=str(repo / "schema.sql"))
        missing = repo / "multistmt" / "missing_table.sql"
        missing.write_text("SELECT * FROM nonexistent;\n")
        result = engine.analyze_file(str(missing))
        assert "SCHEMA-TBL-001" in {i.rule_id for i in result.issues}

    def test_missing_column(self, repo):
        engine = SlowQL(schema_path=str(repo / "schema.sql"))
        missing_col = repo / "multistmt" / "missing_col.sql"
        missing_col.write_text("SELECT nonexistent_col FROM users;\n")
        result = engine.analyze_file(str(missing_col))
        assert "SCHEMA-COL-001" in {i.rule_id for i in result.issues}

    def test_missing_index(self, repo):
        engine = SlowQL(schema_path=str(repo / "schema.sql"))
        query = repo / "multistmt" / "filter_no_index.sql"
        query.write_text("SELECT * FROM users WHERE email = 'test@test.com';\n")
        result = engine.analyze_file(str(query))
        assert "SCHEMA-IDX-001" in {i.rule_id for i in result.issues}
