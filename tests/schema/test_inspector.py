from pathlib import Path

import pytest

from slowql.schema.inspector import SchemaInspector
from slowql.schema.models import ColumnType


@pytest.fixture
def schema_fixture_path():
    """Fixture to provide the path to the schema SQL fixture."""
    return Path(__file__).parent.parent / "fixtures" / "schema.sql"

def test_inspector_initialization():
    """Test that the inspector initializes correctly."""
    # Default
    ins = SchemaInspector()
    assert ins.source is None
    assert ins.dialect == "postgresql"

    # Custom
    ins = SchemaInspector(source="schema.sql", dialect="mysql")
    assert ins.source == "schema.sql"
    assert ins.dialect == "mysql"

    # Normalize postgres
    ins = SchemaInspector(dialect="postgres")
    assert ins.dialect == "postgresql"

def test_inspect_none_source():
    """Test that inspect() returns an empty schema when source is None."""
    ins = SchemaInspector()
    schema = ins.inspect()
    assert len(schema.tables) == 0
    assert schema.dialect == "postgresql"

def test_inspect_from_ddl_file(schema_fixture_path):
    """Test loading schema from a DDL file."""
    ins = SchemaInspector(source=schema_fixture_path)
    schema = ins.inspect()

    assert schema.has_table("users")
    assert schema.has_table("orders")
    assert schema.get_table("users").get_column("email").unique is True

def test_inspect_file_not_found():
    """Test that FileNotFoundError is raised for missing files."""
    ins = SchemaInspector(source="nonexistent.sql")
    with pytest.raises(FileNotFoundError):
        ins.inspect()

def test_from_ddl_string():
    """Test the convenience class method from_ddl_string."""
    ddl = "CREATE TABLE test (id INT PRIMARY KEY);"
    schema = SchemaInspector.from_ddl_string(ddl)

    assert schema.has_table("test")
    assert schema.get_table("test").get_column("id").type == ColumnType.INTEGER

def test_from_ddl_file(schema_fixture_path):
    """Test the convenience class method from_ddl_file."""
    schema = SchemaInspector.from_ddl_file(schema_fixture_path)

    assert schema.has_table("users")
    assert schema.has_table("orders")

def test_inspect_unknown_extension(tmp_path):
    """Test that it tries to treat unknown extensions as DDL files."""
    ddl_file = tmp_path / "schema.txt"
    ddl_file.write_text("CREATE TABLE fallback (id INT);")

    ins = SchemaInspector(source=ddl_file)
    schema = ins.inspect()

    assert schema.has_table("fallback")
