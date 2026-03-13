from pathlib import Path

import pytest

from slowql.schema.ddl_parser import DDLParser
from slowql.schema.models import ColumnType


@pytest.fixture
def parser():
    """Fixture to provide a DDLParser instance with default dialect."""
    return DDLParser(dialect="postgresql")

@pytest.fixture
def schema_fixture_path():
    """Fixture to provide the path to the schema SQL fixture."""
    return Path(__file__).parent.parent / "fixtures" / "schema.sql"

@pytest.fixture
def schema_fixture_ddl(schema_fixture_path):
    """Fixture to provide the content of the schema SQL fixture."""
    return schema_fixture_path.read_text()

def test_parser_initialization():
    """Test that the parser initializes correctly with various dialects."""
    # Default dialect
    p1 = DDLParser()
    assert p1.dialect == "postgresql"

    # Normalize postgres to postgresql
    p2 = DDLParser(dialect="postgres")
    assert p2.dialect == "postgresql"

    # Custom dialect
    p3 = DDLParser(dialect="mysql")
    assert p3.dialect == "mysql"

def test_parse_simple_table(parser):
    """Test parsing a basic CREATE TABLE statement."""
    ddl = "CREATE TABLE users (id INTEGER, name TEXT);"
    schema = parser.parse_ddl(ddl)

    assert schema.has_table("users"), "Table 'users' should exist"
    table = schema.get_table("users")
    assert len(table.columns) == 2, "Table should have 2 columns"

    id_col = table.get_column("id")
    assert id_col.type == ColumnType.INTEGER, "id should be INTEGER"

    name_col = table.get_column("name")
    assert name_col.type == ColumnType.TEXT, "name should be TEXT"

def test_parse_primary_key_inline(parser):
    """Test parsing a column with an inline PRIMARY KEY constraint."""
    ddl = "CREATE TABLE users (id SERIAL PRIMARY KEY);"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    id_col = table.get_column("id")
    assert id_col.primary_key is True, "id should be a primary key"
    assert id_col.nullable is False, "primary key column should not be nullable"

def test_parse_not_null(parser):
    """Test parsing a column with a NOT NULL constraint."""
    ddl = "CREATE TABLE users (email VARCHAR(255) NOT NULL);"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    email_col = table.get_column("email")
    assert email_col.nullable is False, "email should not be nullable"

def test_parse_unique_constraint(parser):
    """Test parsing a column with a UNIQUE constraint."""
    ddl = "CREATE TABLE users (email VARCHAR(255) UNIQUE);"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    email_col = table.get_column("email")
    assert email_col.unique is True, "email should be unique"

def test_parse_default_value(parser):
    """Test parsing a column with a DEFAULT value."""
    ddl = "CREATE TABLE users (created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    created_at_col = table.get_column("created_at")
    assert created_at_col.default is not None, "default value should be set"
    assert "CURRENT_TIMESTAMP" in created_at_col.default

def test_parse_foreign_key(parser):
    """Test parsing a column with a FOREIGN KEY reference."""
    ddl = "CREATE TABLE orders (user_id INTEGER REFERENCES users(id));"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("orders")
    user_id_col = table.get_column("user_id")
    assert user_id_col.foreign_key == "users.id", f"Expected users.id, got {user_id_col.foreign_key}"

def test_parse_create_index(parser):
    """Test parsing a standalone CREATE INDEX statement."""
    ddl = """
    CREATE TABLE users (id INTEGER, email TEXT);
    CREATE INDEX idx_email ON users(email);
    """
    schema = parser.parse_ddl(ddl)

    assert schema.has_table("users")
    table = schema.get_table("users")
    assert len(table.indexes) == 1, "Table should have 1 index"

    index = table.indexes[0]
    assert index.name == "idx_email"
    assert index.columns == ("email",)
    assert index.unique is False

def test_parse_unique_index(parser):
    """Test parsing a CREATE UNIQUE INDEX statement."""
    ddl = """
    CREATE TABLE users (id INTEGER, email TEXT);
    CREATE UNIQUE INDEX idx_email ON users(email);
    """
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    assert table.indexes[0].unique is True

def test_parse_multi_column_index(parser):
    """Test parsing a multi-column index."""
    ddl = """
    CREATE TABLE users (first_name TEXT, last_name TEXT);
    CREATE INDEX idx_name ON users(first_name, last_name);
    """
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    index = table.indexes[0]
    assert index.columns == ("first_name", "last_name")

def test_parse_schema_prefix(parser):
    """Test parsing a table definition with a schema prefix."""
    ddl = "CREATE TABLE public.users (id INTEGER);"
    schema = parser.parse_ddl(ddl)

    table = schema.get_table("users")
    assert table.table_schema == "public"
    assert table.name == "users"

def test_parse_multiple_tables(parser, schema_fixture_ddl):
    """Test parsing multiple tables and indexes from a fixture."""
    schema = parser.parse_ddl(schema_fixture_ddl)

    assert schema.has_table("users")
    assert schema.has_table("orders")

    users = schema.get_table("users")
    assert users.has_column("email")
    assert users.has_column("username")
    assert users.has_index_on(["email"])

    orders = schema.get_table("orders")
    assert orders.has_column("user_id")
    assert orders.get_column("user_id").foreign_key == "users.id"
    assert orders.has_index_on(["user_id"])

def test_type_mapping_integer_types(parser):
    """Test mapping of various integer types."""
    ddl = """
    CREATE TABLE types (
        c1 INTEGER,
        c2 INT,
        c3 SERIAL,
        c4 BIGINT,
        c5 SMALLINT
    );
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.INTEGER
    assert table.get_column("c2").type == ColumnType.INTEGER
    assert table.get_column("c3").type == ColumnType.INTEGER
    assert table.get_column("c4").type == ColumnType.BIGINT
    assert table.get_column("c5").type == ColumnType.SMALLINT

def test_type_mapping_string_types(parser):
    """Test mapping of various string types."""
    ddl = """
    CREATE TABLE types (
        c1 VARCHAR(255),
        c2 TEXT,
        c3 CHAR(10)
    );
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.VARCHAR
    assert table.get_column("c2").type == ColumnType.TEXT
    assert table.get_column("c3").type == ColumnType.CHAR

def test_type_mapping_numeric_types(parser):
    """Test mapping of various numeric types."""
    ddl = """
    CREATE TABLE types (
        c1 DECIMAL(10,2),
        c2 NUMERIC,
        c3 REAL,
        c4 DOUBLE PRECISION
    );
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.DECIMAL
    assert table.get_column("c2").type == ColumnType.DECIMAL
    assert table.get_column("c3").type == ColumnType.FLOAT
    assert table.get_column("c4").type == ColumnType.DOUBLE

def test_type_mapping_datetime_types(parser):
    """Test mapping of Various datetime types."""
    ddl = """
    CREATE TABLE types (
        c1 TIMESTAMP,
        c2 DATE,
        c3 TIME
    );
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.TIMESTAMP
    assert table.get_column("c2").type == ColumnType.DATE
    assert table.get_column("c3").type == ColumnType.TIME

def test_type_mapping_other_types(parser):
    """Test mapping of various other types."""
    ddl = """
    CREATE TABLE types (
        c1 BOOLEAN,
        c2 JSON,
        c3 JSONB
    );
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.BOOLEAN
    assert table.get_column("c2").type == ColumnType.JSON
    assert table.get_column("c3").type == ColumnType.JSONB

def test_type_mapping_unknown(parser):
    """Test that unknown types fallback to ColumnType.UNKNOWN."""
    ddl = "CREATE TABLE types (c1 SOMECUSTOMTYPE);"
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("types")

    assert table.get_column("c1").type == ColumnType.UNKNOWN

def test_parse_empty_ddl(parser):
    """Test parsing an empty DDL string."""
    schema = parser.parse_ddl("")
    assert len(schema.tables) == 0

def test_parse_non_create_statements(parser):
    """Test that non-CREATE statements are skipped."""
    ddl = """
    SELECT * FROM users;
    INSERT INTO users VALUES (1);
    """
    schema = parser.parse_ddl(ddl)
    assert len(schema.tables) == 0

def test_parse_with_comments(parser):
    """Test that comments are handled gracefully."""
    ddl = """
    -- This is a comment
    CREATE TABLE users (id INTEGER);
    /* Multi-line
       comment */
    """
    schema = parser.parse_ddl(ddl)
    assert schema.has_table("users")

def test_has_index_on_integration(parser):
    """Test the integration between DDLParser and Table.has_index_on."""
    ddl = """
    CREATE TABLE users (id INTEGER, email TEXT);
    CREATE INDEX idx_email ON users(email);
    """
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("users")

    assert table.has_index_on(["email"]) is True
    assert table.has_index_on(["id"]) is False
    assert table.has_index_on(["email", "id"]) is False


def test_parse_ddl_invalid_sql_raises_value_error(parser):
    """Test that malformed DDL raises ValueError."""
    with pytest.raises(ValueError, match="Failed to parse DDL"):
        parser.parse_ddl("CREATE TABLE (")


def test_parse_ddl_statement_exception_logs_and_continues(parser, monkeypatch, caplog):
    """Test that statement-level exceptions are caught, logged, and processing continues."""

    def mock_parse_create_table(*_, **__):
        raise RuntimeError("Something went wrong")

    monkeypatch.setattr(parser, "_parse_create_table", mock_parse_create_table)

    ddl = """
    CREATE TABLE users (id INTEGER);
    """

    schema = parser.parse_ddl(ddl)

    assert "Failed to parse statement" in caplog.text
    assert "Something went wrong" in caplog.text
    assert len(schema.tables) == 0


def test_get_table_info_unknown_expression_returns_none(parser):
    """Test _get_table_info with unsupported expression types."""
    from sqlglot import exp

    table_obj, exprs = parser._get_table_info(exp.Star())
    assert table_obj is None
    assert exprs == []


def test_parse_create_table_without_name_returns_none(parser, monkeypatch):
    """Test _parse_create_table with an unnamed table."""
    from sqlglot import exp

    # Monkeypatch to simulate a table object without a name
    monkeypatch.setattr(parser, "_get_table_info", lambda _: (exp.Table(this=exp.Identifier(this="")), []))

    stmt = exp.Create(this=exp.Table(this=exp.Identifier(this="")), kind="TABLE")
    assert parser._parse_create_table(stmt) is None


def test_parse_table_elements_table_level_primary_key(parser):
    """Test parsing table-level PRIMARY KEY constraint."""
    ddl = "CREATE TABLE users (id INTEGER, PRIMARY KEY (id));"
    schema = parser.parse_ddl(ddl)
    table = schema.get_table("users")
    assert "id" in table.primary_key


def test_parse_column_without_name_returns_none(parser):
    """Test _parse_column with a ColumnDef lacking a name."""
    from sqlglot import exp

    col_def = exp.ColumnDef(this=None, kind=exp.DataType.build("int"))
    assert parser._parse_column(col_def) is None


def test_parse_column_default_falls_back_to_args_default(parser):
    """Test that column default falls back to args['default'] if no constraint exists."""
    from sqlglot import exp

    # Construct a ColumnDef and manually set the default arg
    col_def = exp.ColumnDef(
        this=exp.Identifier(this="col", quoted=False),
        kind=exp.DataType.build("int"),
    )
    col_def.set("default", exp.Literal.number(42))

    column = parser._parse_column(col_def)
    assert column.default == "42"


def test_extract_foreign_key_invalid_reference_returns_none(parser):
    """Test _extract_foreign_key with malformed reference."""
    from sqlglot import exp

    # Reference expects 'this' to be a Schema for the current implementation
    ref = exp.Reference(this=exp.Table(this=exp.Identifier(this="other", quoted=False)))
    assert parser._extract_foreign_key(ref) is None


def test_parse_create_index_non_index_returns_none(parser):
    """Test _parse_create_index when stmt.this is not an Index."""
    from sqlglot import exp

    stmt = exp.Create(this=exp.Table(this=exp.Identifier(this="tbl", quoted=False)), kind="INDEX")
    assert parser._parse_create_index(stmt) is None


def test_parse_create_index_missing_name_returns_none(parser):
    """Test _parse_create_index when index name cannot be determined."""
    from sqlglot import exp

    # Index with no name and no 'this' identifier
    index_expr = exp.Index()
    stmt = exp.Create(this=index_expr, kind="INDEX")
    assert parser._parse_create_index(stmt) is None


def test_parse_create_index_missing_table_returns_none(parser):
    """Test _parse_create_index when table is missing."""
    from sqlglot import exp

    index_expr = exp.Index(this=exp.Identifier(this="idx", quoted=False))
    stmt = exp.Create(this=index_expr, kind="INDEX")
    # No Table node in stmt
    assert parser._parse_create_index(stmt) is None


def test_parse_create_index_without_columns_returns_none(parser):
    """Test _parse_create_index when no columns are specified."""
    from sqlglot import exp

    index_expr = exp.Index(this=exp.Identifier(this="idx", quoted=False))
    stmt = exp.Create(this=index_expr, kind="INDEX")
    # Manually append a table node so it passes the table check but fails the column check
    stmt.append("expressions", exp.Table(this=exp.Identifier(this="tbl", quoted=False)))

    assert parser._parse_create_index(stmt) is None


def test_map_sql_type_none_returns_unknown(parser):
    """Test _map_sql_type with None input."""
    assert parser._map_sql_type(None) == ColumnType.UNKNOWN


def test_map_sql_type_malformed_object_returns_unknown(parser):
    """Test _map_sql_type with an object that lacks expected attributes."""

    class Malformed:
        pass

    assert parser._map_sql_type(Malformed()) == ColumnType.UNKNOWN


def test_map_sql_type_malformed_object_raises_attribute_error(parser):
    """Test _map_sql_type when accessing attributes raises AttributeError."""

    class Evil:
        @property
        def this(self):
            raise AttributeError("Evil attribute")

    assert parser._map_sql_type(Evil()) == ColumnType.UNKNOWN


def test_map_sql_type_array_suffix_returns_array(parser):
    """Test _map_sql_type with '[]' suffix in type name."""

    # Using a string representation that includes []
    class MockType:
        def __init__(self):
            self.this = type("this", (), {"name": "MYTYPE[]"})()

    assert parser._map_sql_type(MockType()) == ColumnType.ARRAY


def test_map_sql_type_array_flag_returns_array(parser):
    """Test _map_sql_type with is_array flag for a type not in mapping."""
    from sqlglot import exp

    # Use a type that is NOT in the mapping
    data_type = exp.DataType(this=exp.DataType.Type.UNKNOWN)
    data_type.args["is_array"] = True
    assert parser._map_sql_type(data_type) == ColumnType.ARRAY


def test_get_table_info_plain_table(parser):
    """Test _get_table_info with a plain Table expression."""
    from sqlglot import exp

    table = exp.Table(this=exp.Identifier(this="tbl", quoted=False))
    table_obj, exprs = parser._get_table_info(table)
    assert table_obj is table
    assert exprs == []


def test_extract_foreign_key_missing_expressions_returns_none(parser):
    """Test _extract_foreign_key when reference has table but no column expressions."""
    from sqlglot import exp

    # Mocking a Schema node with a Table node but no expressions
    ref_schema = exp.Schema(this=exp.Table(this=exp.Identifier(this="other", quoted=False)), expressions=[])
    ref = exp.Reference(this=ref_schema)
    assert parser._extract_foreign_key(ref) is None


def test_parse_create_index_use_identifier_as_name(parser):
    """Test _parse_create_index when name is empty but this exists."""
    from sqlglot import exp

    # Index with no name but this=Identifier
    index_expr = exp.Index(this=exp.Identifier(this="idx_ident", quoted=False))
    stmt = exp.Create(this=index_expr, kind="INDEX")
    stmt.append("expressions", exp.Table(this=exp.Identifier(this="tbl", quoted=False)))
    # Need a column too
    col = exp.Column(this=exp.Identifier(this="col", quoted=False))
    stmt.append("expressions", col)

    result = parser._parse_create_index(stmt)
    assert result[1].name == "idx_ident"


def test_parse_ddl_skips_none_table(parser, monkeypatch):
    """Test parse_ddl skips when _parse_create_table returns None."""
    monkeypatch.setattr(parser, "_parse_create_table", lambda _: None)
    ddl = "CREATE TABLE users (id int);"
    schema = parser.parse_ddl(ddl)
    assert len(schema.tables) == 0


def test_parse_ddl_skips_none_index(parser, monkeypatch):
    """Test parse_ddl skips when _parse_create_index returns None."""
    monkeypatch.setattr(parser, "_parse_create_index", lambda _: None)
    ddl = "CREATE INDEX idx ON users(id);"
    schema = parser.parse_ddl(ddl)
    assert len(schema.tables) == 0
