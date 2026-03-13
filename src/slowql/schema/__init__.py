"""
SlowQL Schema Subsystem.

Provides models and tools for database schema representation,
parsing DDL statements, and inspecting schema sources.
"""

from __future__ import annotations

from slowql.schema.ddl_parser import DDLParser
from slowql.schema.inspector import SchemaInspector
from slowql.schema.models import (
    Column,
    ColumnType,
    Index,
    IndexType,
    Schema,
    Table,
)

__all__ = [
    "Column",
    "ColumnType",
    "DDLParser",
    "Index",
    "IndexType",
    "Schema",
    "SchemaInspector",
    "Table",
]
