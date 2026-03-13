from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ColumnType(str, Enum):
    """
    SQL column data types supported by the schema analyzer.
    Supports PostgreSQL, MySQL, BigQuery, and Snowflake types.
    """
    INTEGER = "INTEGER"
    BIGINT = "BIGINT"
    SMALLINT = "SMALLINT"
    VARCHAR = "VARCHAR"
    TEXT = "TEXT"
    CHAR = "CHAR"
    DECIMAL = "DECIMAL"
    NUMERIC = "NUMERIC"
    FLOAT = "FLOAT"
    DOUBLE = "DOUBLE"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"
    DATE = "DATE"
    TIME = "TIME"
    JSON = "JSON"
    JSONB = "JSONB"
    ARRAY = "ARRAY"
    UNKNOWN = "UNKNOWN"


class Column(BaseModel):
    """
    Represents a column in a database table.

    Attributes:
        name: The name of the column.
        type: The data type of the column.
        nullable: Whether the column can contain NULL values.
        default: The default value of the column as a string, or None.
        primary_key: Whether the column is part of the primary key.
        foreign_key: The foreign key reference in the format 'table.column', or None.
        unique: Whether the column has a unique constraint.
        comment: An optional comment or description for the column.
    """
    model_config = ConfigDict(frozen=True)

    name: str
    type: ColumnType
    nullable: bool = True
    default: str | None = None
    primary_key: bool = False
    foreign_key: str | None = None
    unique: bool = False
    comment: str | None = None


class IndexType(str, Enum):
    """
    Supported database index types.
    Includes common types like BTREE and specialized ones like GIN/GIST/BRIN.
    """
    BTREE = "BTREE"
    HASH = "HASH"
    GIN = "GIN"
    GIST = "GIST"
    BRIN = "BRIN"
    FULLTEXT = "FULLTEXT"


class Index(BaseModel):
    """
    Represents an index on a database table.

    Attributes:
        name: The name of the index.
        columns: A tuple of column names included in the index.
        unique: Whether this is a unique index.
        type: The type of the index (e.g., BTREE, GIN).
        where: An optional partial index condition.
    """
    model_config = ConfigDict(frozen=True)

    name: str
    columns: tuple[str, ...]
    unique: bool = False
    type: IndexType = IndexType.BTREE
    where: str | None = None


class Table(BaseModel):
    """
    Represents a database table definition.

    Attributes:
        name: The name of the table.
        table_schema: The schema the table belongs to (default: 'public').
        columns: A tuple of columns in the table.
        indexes: A tuple of indexes defined on the table.
        primary_key: A tuple of column names that make up the primary key.
        comment: An optional comment or description for the table.
    """
    model_config = ConfigDict(frozen=True)

    name: str
    table_schema: str = "public"
    columns: tuple[Column, ...] = ()
    indexes: tuple[Index, ...] = ()
    primary_key: tuple[str, ...] = ()
    comment: str | None = None

    def get_column(self, name: str) -> Column | None:
        """
        Retrieves a column by its name.

        Args:
            name: The name of the column to retrieve.

        Returns:
            The Column object if found, otherwise None.
        """
        for column in self.columns:
            if column.name == name:
                return column
        return None

    def has_column(self, name: str) -> bool:
        """
        Checks if a column exists in the table.

        Args:
            name: The name of the column to check.

        Returns:
            True if the column exists, False otherwise.
        """
        return self.get_column(name) is not None

    def get_index(self, name: str) -> Index | None:
        """
        Retrieves an index by its name.

        Args:
            name: The name of the index to retrieve.

        Returns:
            The Index object if found, otherwise None.
        """
        for index in self.indexes:
            if index.name == name:
                return index
        return None

    def has_index_on(self, columns: list[str]) -> bool:
        """
        Checks if an index exists on the exact sequence of columns.

        Args:
            columns: A list of column names.

        Returns:
            True if an index exists with exactly those columns, False otherwise.
        """
        target_columns = tuple(columns)
        return any(index.columns == target_columns for index in self.indexes)

    def get_primary_key_columns(self) -> tuple[Column, ...]:
        """
        Retrieves all columns that are part of the primary key.

        Returns:
            A tuple of Column objects that form the primary key.
        """
        pk_cols = []
        for col_name in self.primary_key:
            col = self.get_column(col_name)
            if col:
                pk_cols.append(col)
        return tuple(pk_cols)


class Schema(BaseModel):
    """
    Represents a full database schema consisting of multiple tables.

    Attributes:
        tables: A dictionary mapping table names to Table objects.
        dialect: The SQL dialect of the schema (e.g., 'postgresql', 'mysql').
    """
    model_config = ConfigDict(frozen=True)

    tables: dict[str, Table] = Field(default_factory=dict)
    dialect: str = "postgresql"

    def get_table(self, name: str) -> Table | None:
        """
        Retrieves a table by its name.

        Args:
            name: The name of the table to retrieve.

        Returns:
            The Table object if found, otherwise None.
        """
        return self.tables.get(name)

    def has_table(self, name: str) -> bool:
        """
        Checks if a table exists in the schema.

        Args:
            name: The name of the table to check.

        Returns:
            True if the table exists, False otherwise.
        """
        return name in self.tables

    def add_table(self, table: Table) -> Schema:
        """
        Returns a new Schema instance with the added table.
        Since the model is frozen, this creates a new instance.

        Args:
            table: The Table object to add.

        Returns:
            A new Schema instance containing the added table.
        """
        new_tables = self.tables.copy()
        new_tables[table.name] = table
        return Schema(tables=new_tables, dialect=self.dialect)

    def to_dict(self) -> dict[str, Any]:
        """
        Converts the schema to a dictionary representation.

        Returns:
            A dictionary representation of the schema.
        """
        data = self.model_dump()
        for table_data in data.get("tables", {}).values():
            if "table_schema" in table_data:
                table_data["schema"] = table_data.pop("table_schema")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Schema:
        """
        Creates a Schema instance from a dictionary.

        Args:
            data: The dictionary data.

        Returns:
            A new Schema instance.
        """
        # copy to avoid mutating original dictionary passed in
        data = data.copy()
        tables_data = data.get("tables", {})
        if tables_data:
            data["tables"] = {}
            for table_name, table_dict in tables_data.items():
                table_dict_copy = table_dict.copy()
                if "schema" in table_dict_copy:
                    table_dict_copy["table_schema"] = table_dict_copy.pop("schema")
                data["tables"][table_name] = table_dict_copy

        return cls.model_validate(data)
