# slowql/src/slowql/parser/universal.py
"""
Universal SQL parser using sqlglot.

This parser is designed to handle multiple SQL dialects by leveraging
the sqlglot library. It can auto-detect dialects or use a specified one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from slowql.core.exceptions import ParseError, UnsupportedDialectError
from slowql.core.models import Location, Query
from slowql.parser.base import BaseParser

if TYPE_CHECKING:
    from pathlib import Path


class UniversalParser(BaseParser):
    """
    A universal SQL parser powered by sqlglot.

    This parser supports multiple dialects and can parse complex SQL
    into a structured AST.
    """

    # sqlglot supports many dialects, so we leave this empty to signify "all"
    supported_dialects: tuple[str, ...] = ()

    DIALECT_DETECTION_RULES = {
        "bigquery": [r"`[\w-]+\.[\w-]+\.[\w-]+`"],
        "postgres": [r"::", r"\$\d+"],
        "mysql": [r"`"],
        "tsql": [r"\[", r"\]", r"\bTOP\s+\d+"],
        "oracle": [r"\bROWNUM\b"],
        "snowflake": [r"\bLATERAL\s+FLATTEN\b"],
    }

    def __init__(self, dialect: str | None = None) -> None:
        """
        Initialize the universal parser.

        Args:
            dialect: The default dialect to use.

        Raises:
            UnsupportedDialectError: If the dialect is not supported by sqlglot.
        """
        if dialect and dialect not in sqlglot.dialects.DIALECTS:
            raise UnsupportedDialectError(dialect)
        self.default_dialect = dialect

    def parse(
        self, sql: str, *, dialect: str | None = None, file_path: str | Path | None = None
    ) -> list[Query]:
        """
        Parse a SQL string into a list of Query objects.

        Args:
            sql: The SQL string to parse.
            dialect: The SQL dialect to use.
            file_path: Optional path to the source file for location tracking.

        Returns:
            A list of parsed Query objects.

        Raises:
            ParseError: If parsing fails.
        """
        statements = self._split_statements(sql)
        queries = []

        for i, (statement_sql, location) in enumerate(statements):
            try:
                # Use provided dialect, then default, then auto-detect
                effective_dialect = dialect or self.default_dialect or self.detect_dialect(statement_sql)

                # Parse the single statement
                parsed = sqlglot.parse_one(
                    statement_sql,
                    dialect=effective_dialect,
                    error_level=sqlglot.errors.ErrorLevel.WARN,
                )

                # Create Query object
                query = Query(
                    raw=statement_sql,
                    normalized=self.normalize(parsed, dialect=effective_dialect),
                    dialect=effective_dialect or "unknown",
                    location=Location(
                        line=location[0],
                        column=location[1],
                        file=str(file_path) if file_path else None,
                        query_index=i,
                    ),
                    ast=parsed,
                    tables=tuple(self.extract_tables(parsed)),
                    columns=tuple(self.extract_columns(parsed)),
                    query_type=self._get_query_type_from_ast(parsed),
                )
                queries.append(query)

            except SqlglotParseError as e:
                raise ParseError(
                    f"Failed to parse SQL statement: {e}",
                    sql=statement_sql,
                    details=str(e),
                ) from e

        return queries

    def parse_single(
        self, sql: str, *, dialect: str | None = None, file_path: str | Path | None = None
    ) -> Query:
        """
        Parse a single SQL statement.

        Args:
            sql: The SQL string to parse.
            dialect: The SQL dialect.
            file_path: Optional path to the source file.

        Returns:
            A single parsed Query object.

        Raises:
            ParseError: If the input is empty or contains multiple statements.
        """
        # Remove comments and trim whitespace
        clean_sql = re.sub(r"--.*", "", sql)
        clean_sql = re.sub(r"/\*.*?\*/", "", clean_sql, flags=re.DOTALL)
        clean_sql = clean_sql.strip()

        if not clean_sql:
            raise ParseError("No SQL statement found in the input.")

        queries = self.parse(sql, dialect=dialect, file_path=file_path)

        if len(queries) > 1:
            raise ParseError(f"Expected single statement, but found {len(queries)}.")

        return queries[0]

    def detect_dialect(self, sql: str) -> str | None:
        """
        Detect the SQL dialect from a SQL string.

        Args:
            sql: The SQL string.

        Returns:
            The detected dialect name, or None if no specific dialect is detected.
        """
        scores: dict[str, int] = {dialect: 0 for dialect in self.DIALECT_DETECTION_RULES}

        for dialect, patterns in self.DIALECT_DETECTION_RULES.items():
            for pattern in patterns:
                if re.search(pattern, sql, re.IGNORECASE):
                    scores[dialect] += 1

        # Find the dialect with the highest score
        best_dialect = max(scores, key=scores.get)
        if scores[best_dialect] > 0:
            return best_dialect

        return None

    def _split_statements(self, sql: str) -> list[tuple[str, tuple[int, int]]]:
        """
        Split a SQL string into individual statements with location info.

        Tries to use sqlglot's parser first, falls back to semicolon splitting.

        Args:
            sql: The SQL string.

        Returns:
            A list of (statement, (line, col)) tuples.
        """
        try:
            parsed_statements = sqlglot.parse(sql)
            if not parsed_statements:
                return []
            # This approach loses original line/col, so we fallback
            # For now, we'll use a simpler method if this succeeds
            return [(stmt.sql(), (1, 1)) for stmt in parsed_statements]
        except SqlglotParseError:
            # Fallback to simple semicolon splitting
            statements = [s.strip() for s in sql.split(";") if s.strip()]
            return [(stmt, (1, 1)) for stmt in statements]
        except Exception as e:
            # Catch generic exceptions and wrap them
            raise ParseError("An unexpected error occurred during SQL splitting.", details=str(e)) from e

    def normalize(self, ast: Any, dialect: str | None = None) -> str:
        """Normalize a SQL query using its AST."""
        if isinstance(ast, str):
            try:
                parsed_ast = sqlglot.parse_one(ast, read=dialect or self.default_dialect)
            except SqlglotParseError:
                return " ".join(ast.split())
        else:
            parsed_ast = ast

        if not parsed_ast:
            return " ".join(ast.split()) if isinstance(ast, str) else ""
        try:
            # Use sqlglot's generation with pretty printing
            return parsed_ast.sql(dialect=dialect or self.default_dialect, pretty=True)
        except Exception:
            # Fallback for ASTs that can't be regenerated
            return str(parsed_ast)

    def extract_tables(self, ast: Any) -> list[str]:
        """Extract table names from a parsed AST."""
        if isinstance(ast, str):
            try:
                ast = sqlglot.parse_one(ast, read=self.default_dialect)
            except SqlglotParseError:
                return []
        if not ast:
            return []
        return [table.name for table in ast.find_all(exp.Table)]

    def extract_columns(self, ast: Any) -> list[str]:
        """Extract column names from a parsed AST."""
        if isinstance(ast, str):
            try:
                ast = sqlglot.parse_one(ast, read=self.default_dialect)
            except SqlglotParseError:
                return []
        if not ast:
            return []
        return [column.name for column in ast.find_all(exp.Column)]

    def get_query_type(self, sql: str) -> str | None:
        """Get the type of query (SELECT, INSERT, etc.) from a raw SQL string."""
        # Fast path for common keywords
        clean_sql = sql.lstrip().upper()
        for keyword in [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "WITH"
        ]:
            if clean_sql.startswith(keyword):
                return "SELECT" if keyword == "WITH" else keyword
        return None

    def _get_query_type_from_ast(self, ast: Any) -> str | None:
        """Determine query type from the AST node."""
        if isinstance(ast, exp.Select): return "SELECT"
        if isinstance(ast, exp.Insert): return "INSERT"
        if isinstance(ast, exp.Update): return "UPDATE"
        if isinstance(ast, exp.Delete): return "DELETE"
        if isinstance(ast, exp.Merge): return "MERGE"
        if isinstance(ast, exp.Create): return "CREATE"
        if isinstance(ast, exp.Alter): return "ALTER"
        if isinstance(ast, exp.Drop): return "DROP"
        if isinstance(ast, exp.Command): return str(ast.this).upper().split()[0]
        return type(ast).__name__.upper()