from __future__ import annotations

from typing import TYPE_CHECKING

from slowql.schema.ddl_parser import DDLParser
from slowql.schema.models import Schema

if TYPE_CHECKING:
    from slowql.migrations.base import MigrationFile


class MigrationSchemaTracker:
    """
    Tracks the evolution of a database schema through a series of migrations.
    """

    def __init__(self, initial_schema: Schema | None = None) -> None:
        self.initial_schema = initial_schema or Schema()

    def apply_ddl(self, ddl: str) -> Schema:
        """
        Apply a single DDL statement to the current schema state.
        """
        parser = DDLParser(dialect=self.initial_schema.dialect)
        self.initial_schema = parser.apply_ddl(ddl, schema=self.initial_schema)
        return self.initial_schema

    def apply_migrations(self, migrations: list[MigrationFile]) -> Schema:
        """
        Apply a list of migrations in order and return the final schema state.
        """
        current_schema = self.initial_schema
        parser = DDLParser(dialect=current_schema.dialect)

        for migration in migrations:
            current_schema = parser.apply_ddl(migration.content, schema=current_schema)

        return current_schema

    def get_history(self, migrations: list[MigrationFile]) -> list[Schema]:
        """
        Return a list of schema states at each step of the migration process.
        The first element is the initial schema.
        """
        history = [self.initial_schema]
        current_schema = self.initial_schema
        parser = DDLParser(dialect=current_schema.dialect)

        for migration in migrations:
            current_schema = parser.apply_ddl(migration.content, schema=current_schema)
            history.append(current_schema)

        return history
