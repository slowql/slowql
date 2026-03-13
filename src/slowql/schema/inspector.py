import logging
from pathlib import Path

from slowql.schema.ddl_parser import DDLParser
from slowql.schema.models import Schema

logger = logging.getLogger(__name__)

__all__ = ["SchemaInspector"]


class SchemaInspector:
    """
    Unified interface for loading database schemas from various sources.

    Supports loading from DDL files, DDL strings, and (future) live databases.
    """

    def __init__(self, source: str | Path | None = None, dialect: str = "postgresql") -> None:
        """
        Initialize the SchemaInspector.

        Args:
            source: Path to a DDL file, or None for manual schema building.
            dialect: The SQL dialect to use (e.g., 'postgresql', 'mysql').
        """
        self.source = source
        self.dialect = "postgresql" if dialect == "postgres" else dialect

    def inspect(self) -> Schema:
        """
        Inspect the source and return a Schema object.

        Returns:
            A populated Schema object.

        Raises:
            FileNotFoundError: If the source file is not found.
            ValueError: If the source type cannot be determined.
        """
        if self.source is None:
            return Schema(dialect=self.dialect)

        source_str = str(self.source)

        if source_str.endswith(".sql"):
            return self._inspect_from_ddl()

        # Fallback to treating as DDL file if it doesn't have a known extension
        # but is provided as a path.
        return self._inspect_from_ddl()

    def _inspect_from_ddl(self) -> Schema:
        """
        Load schema from a DDL file.

        Returns:
            A populated Schema object.

        Raises:
            FileNotFoundError: If the DDL file does not exist.
        """
        path = Path(str(self.source))
        if not path.exists():
            raise FileNotFoundError(f"DDL file not found: {path}")

        logger.info("Loading schema from DDL file: %s", path)
        ddl_content = path.read_text()
        parser = DDLParser(dialect=self.dialect)
        return parser.parse_ddl(ddl_content)

    @classmethod
    def from_ddl_string(cls, ddl: str, dialect: str = "postgresql") -> Schema:
        """
        Convenience method to parse a DDL string directly.

        Args:
            ddl: The SQL DDL string.
            dialect: The SQL dialect.

        Returns:
            A populated Schema object.
        """
        parser = DDLParser(dialect=dialect)
        return parser.parse_ddl(ddl)

    @classmethod
    def from_ddl_file(cls, path: str | Path, dialect: str = "postgresql") -> Schema:
        """
        Convenience method to load from a DDL file.

        Args:
            path: Path to the DDL file.
            dialect: The SQL dialect.

        Returns:
            A populated Schema object.
        """
        inspector = cls(source=path, dialect=dialect)
        return inspector.inspect()

    # TODO: Add database connection introspection (PostgreSQL, MySQL)
    # TODO: Add SQLAlchemy model inspection
    # TODO: Add Django model inspection
    # TODO: Add auto-discovery from project structure
