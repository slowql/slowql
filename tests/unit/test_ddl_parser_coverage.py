import pytest

from slowql.schema.ddl_parser import DDLParser


def test_ddl_parser_basic():
    parser = DDLParser(dialect="postgresql")
    schema = parser.parse_ddl("""
    CREATE TABLE users (
        id INT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'active'
    );
    CREATE INDEX idx_users_email ON users(email);
    """)

    assert "users" in schema.tables
    table = schema.tables["users"]

    assert table.name == "users"
    assert len(table.columns) == 3
    assert table.has_column("id")
    assert table.has_column("email")
    assert table.has_column("status")

    id_col = table.get_column("id")
    assert id_col.primary_key is True

    email_col = table.get_column("email")
    assert email_col.unique is True
    assert email_col.nullable is False

    status_col = table.get_column("status")
    assert "active" in status_col.default

    assert len(table.indexes) == 1
    assert table.indexes[0].name == "idx_users_email"

def test_ddl_parser_invalid_sql():
    parser = DDLParser()
    with pytest.raises(ValueError):
        parser.parse_ddl("CREATE TABLE ;;; SYNTAX ERROR")

def test_ddl_parser_unsupported_statement():
    parser = DDLParser()
    schema = parser.parse_ddl("SELECT * FROM users;")
    # Just ignores it
    assert len(schema.tables) == 0

def test_ddl_parser_foreign_key():
    parser = DDLParser()
    schema = parser.parse_ddl("""
    CREATE TABLE orders (
        id INT PRIMARY KEY,
        user_id INT REFERENCES users(id)
    );
    """)
    col = schema.tables["orders"].get_column("user_id")
    assert col.foreign_key == "users.id"

def test_ddl_parser_table_constraints():
    parser = DDLParser()
    schema = parser.parse_ddl("""
    CREATE TABLE t (
        a INT,
        b INT,
        PRIMARY KEY (a, b)
    );
    """)
    assert "a" in schema.tables["t"].primary_key
    assert "b" in schema.tables["t"].primary_key

def test_ddl_parser_index_on_missing_table():
    parser = DDLParser()
    # Table t doesn't exist in the DDL
    schema = parser.parse_ddl("CREATE INDEX idx ON t(a);")
    assert len(schema.tables) == 0

def test_ddl_parser_data_types():
    parser = DDLParser()
    schema = parser.parse_ddl("""
    CREATE TABLE types (
        c1 SERIAL,
        c2 TEXT,
        c3 DECIMAL(10,2),
        c4 BOOLEAN,
        c5 TIMESTAMP,
        c6 JSONB,
        c7 INT[],
        c8 UNKNOWN_TYPE
    );
    """)

    t = schema.tables["types"]
    from slowql.schema.models import ColumnType
    assert t.get_column("c1").type == ColumnType.INTEGER
    assert t.get_column("c2").type == ColumnType.TEXT
    assert t.get_column("c3").type == ColumnType.DECIMAL
    assert t.get_column("c4").type == ColumnType.BOOLEAN
    assert t.get_column("c5").type == ColumnType.TIMESTAMP
    assert t.get_column("c6").type == ColumnType.JSONB
    assert t.get_column("c7").type == ColumnType.ARRAY
    assert t.get_column("c8").type == ColumnType.UNKNOWN

def test_ddl_parser_index_formats():
    parser = DDLParser()
    schema = parser.parse_ddl("""
    CREATE TABLE t (a INT, b INT);
    CREATE UNIQUE INDEX u_idx ON t(a);
    """)
    idx = schema.tables["t"].indexes[0]
    assert idx.unique is True
    assert "a" in idx.columns

def test_ddl_parser_empty_index_name():
    parser = DDLParser()
    # No explicit index name, sqlglot parses it slightly differently
    _ = parser.parse_ddl("""
    CREATE TABLE t (a INT);
    CREATE INDEX ON t(a);
    """)
    # If it parses, just check it didn't crash
    pass

def test_ddl_parser_schema_qualification():
    parser = DDLParser()
    schema = parser.parse_ddl("""
    CREATE TABLE myschema.t (a INT);
    """)
    assert "t" in schema.tables
    assert schema.tables["t"].table_schema == "myschema"
