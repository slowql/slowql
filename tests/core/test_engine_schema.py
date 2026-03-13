
from slowql.core.engine import SlowQL
from slowql.core.models import Severity
from slowql.schema.models import Column, ColumnType, Schema, Table


def test_engine_init_with_schema():
    schema = Schema(
        tables={
            "users": Table(
                name="users",
                columns=(Column(name="id", type=ColumnType.INTEGER),)
            )
        }
    )
    engine = SlowQL(schema=schema)
    assert engine.schema == schema

def test_engine_with_schema_method():
    schema = Schema(tables={})
    engine = SlowQL().with_schema(schema=schema)
    assert engine.schema == schema

def test_engine_with_schema_path(tmp_path):
    ddl_file = tmp_path / "schema.sql"
    ddl_file.write_text("CREATE TABLE users (id INT);")

    engine = SlowQL(schema_path=ddl_file)
    assert engine.schema is not None
    assert "users" in engine.schema.tables

def test_run_schema_rules_table_exists():
    schema = Schema(
        tables={
            "users": Table(
                name="users",
                columns=(Column(name="id", type=ColumnType.INTEGER),)
            )
        }
    )
    engine = SlowQL(schema=schema)

    # Existing table - no issue
    result = engine.analyze("SELECT * FROM users")
    schema_issues = [i for i in result.issues if i.rule_id == "SCHEMA-TBL-001"]
    assert len(schema_issues) == 0

    # Non-existent table - issue
    result = engine.analyze("SELECT * FROM missing_table")
    schema_issues = [i for i in result.issues if i.rule_id == "SCHEMA-TBL-001"]
    assert len(schema_issues) == 1
    assert schema_issues[0].message == "Table 'missing_table' does not exist in schema"
    assert schema_issues[0].severity == Severity.CRITICAL

def test_run_schema_rules_column_exists():
    schema = Schema(
        tables={
            "users": Table(
                name="users",
                columns=(Column(name="id", type=ColumnType.INTEGER),)
            )
        }
    )
    engine = SlowQL(schema=schema)

    # Existing column - no issue
    result = engine.analyze("SELECT id FROM users")
    schema_issues = [i for i in result.issues if i.rule_id == "SCHEMA-COL-001"]
    assert len(schema_issues) == 0

    # Non-existent column - issue
    result = engine.analyze("SELECT missing_col FROM users")
    schema_issues = [i for i in result.issues if i.rule_id == "SCHEMA-COL-001"]
    assert len(schema_issues) == 1
    assert "missing_col" in schema_issues[0].message
