import logging
from typing import Any

import sqlglot
from sqlglot import exp

from slowql.schema.models import (
    Column,
    ColumnType,
    Index,
    Schema,
    Table,
)

logger = logging.getLogger(__name__)


class DDLParser:
    """
    Parser for Data Definition Language (DDL) statements.

    Uses sqlglot to parse CREATE TABLE and CREATE INDEX statements
    and converts them into SlowQL schema models.
    """

    def __init__(self, dialect: str = "postgresql") -> None:
        """
        Initialize the DDLParser.

        Args:
            dialect: The SQL dialect to parse (e.g., 'postgresql', 'mysql').
        """
        self.dialect = "postgresql" if dialect == "postgres" else dialect

    def parse_ddl(self, ddl: str) -> Schema:
        """
        Parse a complete DDL string and return a Schema.

        Args:
            ddl: A string containing one or more SQL statements.

        Returns:
            A populated Schema object containing parsed tables.

        Raises:
            ValueError: If parsing the complete DDL string fails.
        """
        return self.apply_ddl(ddl, Schema(dialect=self.dialect))

    def apply_ddl(self, ddl: str, schema: Schema) -> Schema:
        """
        Apply DDL statements to an existing schema and return the updated schema.
        """
        sqlglot_dialect = "postgres" if self.dialect == "postgresql" else self.dialect
        try:
            statements = sqlglot.parse(ddl, dialect=sqlglot_dialect)
        except Exception as e:
            raise ValueError(f"Failed to parse DDL: {e}") from e

        current_schema = schema
        indexes_to_add: list[tuple[str, Index]] = []

        for stmt in statements:
            try:
                if isinstance(stmt, exp.Create):
                    if isinstance(stmt.this, (exp.Schema, exp.Table)):
                        table = self._parse_create_table(stmt)
                        if table:
                            current_schema = current_schema.add_table(table)
                    elif isinstance(stmt.this, exp.Index):
                        result = self._parse_create_index(stmt)
                        if result:
                            indexes_to_add.append(result)
                elif isinstance(stmt, exp.Drop):
                    if isinstance(stmt.this, exp.Table):
                        table_name = stmt.this.name
                        if current_schema.has_table(table_name):
                            new_tables = current_schema.tables.copy()
                            new_tables.pop(table_name)
                            current_schema = Schema(tables=new_tables, dialect=current_schema.dialect)
                elif isinstance(stmt, exp.Alter):
                    current_schema = self._apply_alter(stmt, current_schema)
            except Exception as e:
                logger.warning("Failed to parse statement %s: %s", stmt.sql(), e)
                continue

        # Add indexes to tables
        for table_name, index in indexes_to_add:
            if current_schema.has_table(table_name):
                table = current_schema.get_table(table_name)
                if table:
                    new_indexes = (*table.indexes, index)
                    new_table = Table(
                        name=table.name,
                        table_schema=table.table_schema,
                        columns=table.columns,
                        indexes=new_indexes,
                        primary_key=table.primary_key,
                        comment=table.comment
                    )
                    current_schema = current_schema.add_table(new_table)

        return current_schema

    def _apply_alter(self, stmt: exp.Alter, schema: Schema) -> Schema:
        """Apply an ALTER TABLE statement to the schema."""
        table_node = stmt.find(exp.Table)
        if not table_node or not table_node.name:
            return schema
        
        table_name = table_node.name
        if not schema.has_table(table_name):
            return schema

        table = schema.get_table(table_name)
        if not table:
            return schema

        new_columns = list(table.columns)
        
        for action in stmt.args.get("actions", []):
            # Add column
            if isinstance(action, exp.ColumnDef):
                col = self._parse_column(action)
                if col:
                    new_columns.append(col)
            elif hasattr(action, 'arg_key') and action.arg_key == 'add_column':
                 col_def = action.args.get("this")
                 if isinstance(col_def, exp.ColumnDef):
                     col = self._parse_column(col_def)
                     if col:
                         new_columns.append(col)
            # Drop column
            elif isinstance(action, exp.Drop) and isinstance(action.this, exp.Column):
                col_name = action.this.name
                new_columns = [c for c in new_columns if c.name != col_name]
            elif hasattr(action, 'kind') and str(action.kind).upper() == 'DROP':
                if hasattr(action, 'this') and isinstance(action.this, exp.Column):
                    col_name = action.this.name
                    new_columns = [c for c in new_columns if c.name != col_name]

        new_table = Table(
            name=table.name,
            table_schema=table.table_schema,
            columns=tuple(new_columns),
            indexes=table.indexes,
            primary_key=table.primary_key,
            comment=table.comment
        )
        return schema.add_table(new_table)

    def _parse_create_table(self, stmt: exp.Create) -> Table | None:
        """
        Parse a CREATE TABLE statement.

        Args:
            stmt: The sqlglot Create statement expression.

        Returns:
            A Table object, or None if the table name cannot be extracted.
        """
        table_obj, expressions = self._get_table_info(stmt.this)
        if not (table_obj and table_obj.name):
            return None

        columns: list[Column] = []
        primary_key_cols: list[str] = []

        self._parse_table_elements(expressions, columns, primary_key_cols)

        return Table(
            name=table_obj.name,
            table_schema=getattr(table_obj, "db", "public") or "public",
            columns=tuple(columns),
            primary_key=tuple(primary_key_cols),
        )

    def _get_table_info(self, table_expr: exp.Expression) -> tuple[exp.Table | None, list[exp.Expression]]:
        """Extract table object and column/constraint expressions."""
        if isinstance(table_expr, exp.Schema):
            table_obj = table_expr.this if isinstance(table_expr.this, exp.Table) else None
            return table_obj, table_expr.expressions
        if isinstance(table_expr, exp.Table):
            return table_expr, []
        return None, []

    def _parse_table_elements(self, expressions: list[exp.Expression], columns: list[Column], pk_cols: list[str]) -> None:
        """Parse column definitions and table-level constraints."""
        for col_def in expressions:
            if isinstance(col_def, exp.ColumnDef):
                column = self._parse_column(col_def)
                if column:
                    columns.append(column)
                    if column.primary_key:
                        pk_cols.append(column.name)
            elif isinstance(col_def, exp.PrimaryKey):
                pk_cols.extend(col.name for col in getattr(col_def, "expressions", []) if hasattr(col, "name"))

    def _parse_column(self, col_def: exp.ColumnDef) -> Column | None:
        """
        Parse a column definition.

        Args:
            col_def: The sqlglot ColumnDef expression.

        Returns:
            A Column object, or None if the column name cannot be extracted.
        """
        col_name = col_def.name
        if not col_name:
            return None

        # Extract type
        col_type = self._map_sql_type(col_def.args.get("kind"))

        # Parse constraints
        nullable, primary_key, unique, foreign_key, default_val = self._parse_column_constraints(
            getattr(col_def, "constraints", [])
        )

        # fallback to args.get("default") if not in constraints
        if default_val is None:
            default_expr = col_def.args.get("default")
            if default_expr:
                default_val = default_expr.sql()

        return Column(
            name=col_name,
            type=col_type,
            nullable=nullable,
            primary_key=primary_key,
            unique=unique,
            foreign_key=foreign_key,
            default=default_val,
        )

    def _parse_column_constraints(
        self, constraints: list[exp.ColumnConstraint]
    ) -> tuple[bool, bool, bool, str | None, str | None]:
        """Parse column-level constraints. Returns (nullable, primary_key, unique, foreign_key, default)."""
        nullable = True
        primary_key = False
        unique = False
        foreign_key = None
        default_val = None

        for constraint in constraints:
            kind = getattr(constraint, "kind", constraint)
            if isinstance(kind, exp.NotNullColumnConstraint):
                nullable = False
            elif isinstance(kind, exp.PrimaryKeyColumnConstraint):
                primary_key = True
                nullable = False
            elif isinstance(kind, exp.UniqueColumnConstraint):
                unique = True
            elif isinstance(kind, exp.Reference):
                foreign_key = self._extract_foreign_key(kind)
            elif isinstance(kind, exp.DefaultColumnConstraint):
                if hasattr(kind, "this"):
                    default_val = kind.this.sql()

        return nullable, primary_key, unique, foreign_key, default_val

    def _extract_foreign_key(self, ref: exp.Reference) -> str | None:
        """Extract foreign key reference in 'table.column' format."""
        if not (getattr(ref, "this", None) and isinstance(ref.this, exp.Schema)):
            return None

        ref_table = ref.this.this.name if ref.this.this else None
        if not (ref_table and getattr(ref.this, "expressions", None)):
            return None

        ref_col = ref.this.expressions[0].name
        return f"{ref_table}.{ref_col}" if ref_col else None

    def _parse_create_index(self, stmt: exp.Create) -> tuple[str, Index] | None:
        """
        Parse a CREATE INDEX statement.

        Args:
            stmt: The sqlglot Create statement expression for an index.

        Returns:
            A tuple containing the table name and the Index object, or None if parsing fails.
        """
        index_expr = stmt.this
        if not isinstance(index_expr, exp.Index):
            return None

        # Extract index name
        index_name = index_expr.name
        if not index_name and index_expr.this:
            index_name = getattr(index_expr.this, "name", str(index_expr.this))

        if not index_name:
            return None

        # Extract table name
        table_node = stmt.find(exp.Table)
        if not table_node or not table_node.name:
            return None
        table_name = table_node.name

        # Extract indexed columns
        columns: list[str] = []
        for col in stmt.find_all(exp.Column):
            if col.name:
                columns.append(col.name)

        if not columns:
            return None

        unique = stmt.args.get("unique") is True

        index = Index(
            name=index_name,
            columns=tuple(columns),
            unique=unique,
        )

        return (table_name, index)

    def _map_sql_type(self, data_type: Any) -> ColumnType:
        """
        Map a sqlglot DataType expression to a ColumnType enum.

        Args:
            data_type: The DataType expression from sqlglot.

        Returns:
            The mapped ColumnType.
        """
        if not data_type:
            return ColumnType.UNKNOWN

        try:
            if hasattr(data_type, "this") and data_type.this:
                type_name = data_type.this.name.upper() if hasattr(data_type.this, 'name') else str(data_type.this).upper()
            else:
                return ColumnType.UNKNOWN
        except AttributeError:
            return ColumnType.UNKNOWN

        mapping = {
            "INT": ColumnType.INTEGER,
            "INTEGER": ColumnType.INTEGER,
            "SERIAL": ColumnType.INTEGER,
            "BIGSERIAL": ColumnType.INTEGER,
            "BIGINT": ColumnType.BIGINT,
            "SMALLINT": ColumnType.SMALLINT,
            "VARCHAR": ColumnType.VARCHAR,
            "CHARACTER VARYING": ColumnType.VARCHAR,
            "TEXT": ColumnType.TEXT,
            "CHAR": ColumnType.CHAR,
            "CHARACTER": ColumnType.CHAR,
            "DECIMAL": ColumnType.DECIMAL,
            "NUMERIC": ColumnType.DECIMAL,
            "FLOAT": ColumnType.FLOAT,
            "REAL": ColumnType.FLOAT,
            "DOUBLE": ColumnType.DOUBLE,
            "DOUBLE PRECISION": ColumnType.DOUBLE,
            "BOOLEAN": ColumnType.BOOLEAN,
            "BOOL": ColumnType.BOOLEAN,
            "TIMESTAMP": ColumnType.TIMESTAMP,
            "TIMESTAMPTZ": ColumnType.TIMESTAMP,
            "DATE": ColumnType.DATE,
            "TIME": ColumnType.TIME,
            "TIMETZ": ColumnType.TIME,
            "JSON": ColumnType.JSON,
            "JSONB": ColumnType.JSONB,
            "ARRAY": ColumnType.ARRAY,
        }

        if type_name in mapping:
            return mapping[type_name]

        if "[]" in type_name or getattr(data_type, "args", {}).get("is_array"):
            return ColumnType.ARRAY

        return ColumnType.UNKNOWN
