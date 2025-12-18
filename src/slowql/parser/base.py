# slowql/src/slowql/parser/base.py
"""
Abstract base class for SQL parsers.

This module defines the interface that all SQL parsers must implement,
allowing for different parsing backends while maintaining a consistent API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slowql.core.models import Query


class BaseParser(ABC):
    """
    Abstract base class for SQL parsers.

    All SQL parsers in SlowQL must inherit from this class and
    implement the required methods.

    Attributes:
        dialect: The SQL dialect this parser handles (or None for universal).
        supported_dialects: Tuple of dialect names this parser can handle.
    """

    dialect: str | None = None
    supported_dialects: tuple[str, ...] = ()

    @abstractmethod
    def parse(
        self,
        sql: str,
        *,
        dialect: str | None = None,
        file_path: str | None = None,
    ) -> list[Query]:
        """
        Parse SQL string into Query objects.

        Args:
            sql: The SQL string to parse. May contain multiple statements.
            dialect: Optional dialect hint. If None, auto-detection is attempted.
            file_path: Optional file path for location tracking in errors.

        Returns:
            List of Query objects representing the parsed statements.

        Raises:
            ParseError: If the SQL cannot be parsed.
        """
        ...

    @abstractmethod
    def parse_single(
        self,
        sql: str,
        *,
        dialect: str | None = None,
        file_path: str | None = None,
    ) -> Query:
        """
        Parse a single SQL statement.

        Args:
            sql: The SQL string containing exactly one statement.
            dialect: Optional dialect hint.
            file_path: Optional file path for location tracking.

        Returns:
            A single Query object.

        Raises:
            ParseError: If the SQL cannot be parsed or contains multiple statements.
        """
        ...

    @abstractmethod
    def detect_dialect(self, sql: str) -> str | None:
        """
        Attempt to detect the SQL dialect from the query.

        Args:
            sql: The SQL string to analyze.

        Returns:
            Detected dialect name, or None if detection failed.
        """
        ...

    @abstractmethod
    def normalize(self, sql: str, *, dialect: str | None = None) -> str:
        """
        Normalize/format SQL for consistent comparison.

        Args:
            sql: The SQL string to normalize.
            dialect: Optional dialect hint.

        Returns:
            Normalized SQL string.
        """
        ...

    @abstractmethod
    def extract_tables(self, sql: str, *, dialect: str | None = None) -> list[str]:
        """
        Extract table names referenced in a query.

        Args:
            sql: The SQL string to analyze.
            dialect: Optional dialect hint.

        Returns:
            List of table names (may include schema prefixes).
        """
        ...

    @abstractmethod
    def extract_columns(self, sql: str, *, dialect: str | None = None) -> list[str]:
        """
        Extract column names referenced in a query.

        Args:
            sql: The SQL string to analyze.
            dialect: Optional dialect hint.

        Returns:
            List of column names (may include table prefixes).
        """
        ...

    @abstractmethod
    def get_query_type(self, sql: str) -> str | None:
        """
        Determine the type of SQL statement.

        Args:
            sql: The SQL string to analyze.

        Returns:
            Query type (SELECT, INSERT, UPDATE, DELETE, etc.) or None.
        """
        ...

    def supports_dialect(self, dialect: str) -> bool:
        """
        Check if this parser supports a given dialect.

        Args:
            dialect: The dialect name to check.

        Returns:
            True if the dialect is supported.
        """
        if not self.supported_dialects:
            return True  # Universal parser
        return dialect.lower() in (d.lower() for d in self.supported_dialects)
