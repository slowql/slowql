import pytest
from pydantic import ValidationError

from slowql.schema.models import (
    Column,
    ColumnType,
    Index,
    IndexType,
    Schema,
    Table,
)


# Fixtures
@pytest.fixture
def sample_column():
    return Column(
        name="email",
        type=ColumnType.VARCHAR,
        nullable=False,
        unique=True,
    )


@pytest.fixture
def sample_table():
    return Table(
        name="users",
        columns=(
            Column(name="id", type=ColumnType.INTEGER, primary_key=True),
            Column(name="email", type=ColumnType.VARCHAR, nullable=False),
        ),
        indexes=(
            Index(name="idx_email", columns=("email",)),
        ),
        primary_key=("id",),
    )


@pytest.fixture
def sample_schema(sample_table):
    return Schema(tables={sample_table.name: sample_table})


# Tests start here
def test_column_type_enum():
    # Verify all enum values exist
    assert ColumnType.INTEGER == "INTEGER"
    assert ColumnType.BIGINT == "BIGINT"
    assert ColumnType.SMALLINT == "SMALLINT"
    assert ColumnType.VARCHAR == "VARCHAR"
    assert ColumnType.TEXT == "TEXT"
    assert ColumnType.CHAR == "CHAR"
    assert ColumnType.DECIMAL == "DECIMAL"
    assert ColumnType.NUMERIC == "NUMERIC"
    assert ColumnType.FLOAT == "FLOAT"
    assert ColumnType.DOUBLE == "DOUBLE"
    assert ColumnType.BOOLEAN == "BOOLEAN"
    assert ColumnType.TIMESTAMP == "TIMESTAMP"
    assert ColumnType.DATE == "DATE"
    assert ColumnType.TIME == "TIME"
    assert ColumnType.JSON == "JSON"
    assert ColumnType.JSONB == "JSONB"
    assert ColumnType.ARRAY == "ARRAY"
    assert ColumnType.UNKNOWN == "UNKNOWN"

    # Test enum membership
    assert "VARCHAR" in [e.value for e in ColumnType]


def test_index_type_enum():
    # Verify all enum values exist
    assert IndexType.BTREE == "BTREE"
    assert IndexType.HASH == "HASH"
    assert IndexType.GIN == "GIN"
    assert IndexType.GIST == "GIST"
    assert IndexType.BRIN == "BRIN"
    assert IndexType.FULLTEXT == "FULLTEXT"

    # Test enum membership
    assert "GIN" in [e.value for e in IndexType]


def test_column_creation_minimal():
    col = Column(name="id", type=ColumnType.INTEGER)
    assert col.name == "id"
    assert col.type == ColumnType.INTEGER
    assert col.nullable is True
    assert col.default is None
    assert col.primary_key is False
    assert col.foreign_key is None
    assert col.unique is False
    assert col.comment is None


def test_column_creation_full():
    col = Column(
        name="user_id",
        type=ColumnType.BIGINT,
        nullable=False,
        default="0",
        primary_key=True,
        foreign_key="other_table.id",
        unique=True,
        comment="The user ID",
    )
    assert col.name == "user_id"
    assert col.type == ColumnType.BIGINT
    assert col.nullable is False
    assert col.default == "0"
    assert col.primary_key is True
    assert col.foreign_key == "other_table.id"
    assert col.unique is True
    assert col.comment == "The user ID"


def test_column_immutability(sample_column):
    with pytest.raises(ValidationError):
        sample_column.name = "new_name"


def test_column_foreign_key():
    col = Column(name="user_id", type=ColumnType.INTEGER, foreign_key="users.id")
    assert col.foreign_key == "users.id"


def test_index_creation_single_column():
    idx = Index(name="idx_email", columns=("email",))
    assert idx.name == "idx_email"
    assert idx.columns == ("email",)
    assert idx.unique is False
    assert idx.type == IndexType.BTREE
    assert idx.where is None


def test_index_creation_multi_column():
    idx = Index(name="idx_name", columns=("first_name", "last_name"))
    assert idx.columns == ("first_name", "last_name")


def test_index_unique():
    idx = Index(name="idx_email_unique", columns=("email",), unique=True)
    assert idx.unique is True


def test_index_partial():
    idx = Index(name="idx_active", columns=("id",), where="status = 'active'")
    assert idx.where == "status = 'active'"


def test_index_immutability():
    idx = Index(name="idx_email", columns=("email",))
    with pytest.raises(ValidationError):
        idx.name = "new_name"


def test_table_creation_empty():
    table = Table(name="users")
    assert table.name == "users"
    assert table.table_schema == "public"
    assert table.columns == ()
    assert table.indexes == ()
    assert table.primary_key == ()
    assert table.comment is None


def test_table_creation_with_columns():
    table = Table(
        name="users",
        columns=(
            Column(name="id", type=ColumnType.INTEGER),
            Column(name="email", type=ColumnType.VARCHAR),
            Column(name="created_at", type=ColumnType.TIMESTAMP),
        )
    )
    assert len(table.columns) == 3


def test_table_get_column_exists(sample_table):
    col = sample_table.get_column("email")
    assert col is not None
    assert col.name == "email"
    assert col.type == ColumnType.VARCHAR


def test_table_get_column_not_exists(sample_table):
    col = sample_table.get_column("nonexistent")
    assert col is None


def test_table_get_column_case_sensitive(sample_table):
    col = sample_table.get_column("Email")
    assert col is None


def test_table_has_column():
    table = Table(
        name="users",
        columns=(Column(name="id", type=ColumnType.INTEGER),)
    )
    assert table.has_column("id") is True
    assert table.has_column("missing") is False


def test_table_get_index(sample_table):
    idx = sample_table.get_index("idx_email")
    assert idx is not None
    assert idx.name == "idx_email"

    missing_idx = sample_table.get_index("missing")
    assert missing_idx is None


def test_table_has_index_on_exact_match(sample_table):
    assert sample_table.has_index_on(["email"]) is True


def test_table_has_index_on_multi_column():
    table = Table(
        name="users",
        indexes=(Index(name="idx_name", columns=("first_name", "last_name")),)
    )
    assert table.has_index_on(["first_name", "last_name"]) is True


def test_table_has_index_on_wrong_order():
    table = Table(
        name="users",
        indexes=(Index(name="idx_name", columns=("first_name", "last_name")),)
    )
    assert table.has_index_on(["last_name", "first_name"]) is False


def test_table_has_index_on_partial_match():
    table = Table(
        name="users",
        indexes=(Index(name="idx_name", columns=("first_name", "last_name")),)
    )
    assert table.has_index_on(["first_name"]) is False


def test_table_get_primary_key_columns(sample_table):
    pk_cols = sample_table.get_primary_key_columns()
    assert len(pk_cols) == 1
    assert pk_cols[0].name == "id"


def test_table_get_primary_key_columns_composite():
    table = Table(
        name="user_roles",
        columns=(
            Column(name="user_id", type=ColumnType.INTEGER),
            Column(name="role_id", type=ColumnType.INTEGER),
        ),
        primary_key=("user_id", "role_id")
    )
    pk_cols = table.get_primary_key_columns()
    assert len(pk_cols) == 2
    assert pk_cols[0].name == "user_id"
    assert pk_cols[1].name == "role_id"


def test_table_get_primary_key_columns_missing_column():
    table = Table(
        name="users",
        columns=(Column(name="id", type=ColumnType.INTEGER),),
        primary_key=("id", "missing_col")
    )
    pk_cols = table.get_primary_key_columns()
    assert len(pk_cols) == 1
    assert pk_cols[0].name == "id"


def test_table_immutability(sample_table):
    with pytest.raises(ValidationError):
        sample_table.name = "new_name"


def test_schema_creation_empty():
    schema = Schema()
    assert schema.tables == {}
    assert schema.dialect == "postgresql"


def test_schema_get_table_exists(sample_schema):
    table = sample_schema.get_table("users")
    assert table is not None
    assert table.name == "users"


def test_schema_get_table_not_exists(sample_schema):
    table = sample_schema.get_table("missing")
    assert table is None


def test_schema_has_table(sample_schema):
    assert sample_schema.has_table("users") is True
    assert sample_schema.has_table("missing") is False


def test_schema_add_table(sample_schema):
    new_table = Table(name="posts", columns=(Column(name="id", type=ColumnType.INTEGER),))
    new_schema = sample_schema.add_table(new_table)

    assert new_schema is not sample_schema
    assert len(new_schema.tables) == 2
    assert "posts" in new_schema.tables

    # Original schema remains unmodified
    assert len(sample_schema.tables) == 1
    assert "posts" not in sample_schema.tables


def test_schema_to_dict(sample_schema):
    data = sample_schema.to_dict()
    assert "tables" in data
    assert "users" in data["tables"]
    assert data["tables"]["users"]["name"] == "users"
    assert data["dialect"] == "postgresql"


def test_schema_from_dict(sample_schema):
    data = sample_schema.to_dict()
    schema = Schema.from_dict(data)
    assert isinstance(schema, Schema)
    assert "users" in schema.tables
    assert schema.tables["users"].name == "users"


def test_schema_round_trip(sample_schema):
    data = sample_schema.to_dict()
    schema2 = Schema.from_dict(data)
    assert sample_schema == schema2


def test_schema_immutability(sample_schema):
    with pytest.raises(ValidationError):
        sample_schema.dialect = "mysql"
