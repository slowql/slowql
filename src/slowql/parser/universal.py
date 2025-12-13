# slowql/src/slowql/parser/universal.py
"""
Universal SQL parser supporting multiple dialects.

This parser uses sqlglot as the backend for parsing SQL across
different database dialects. It provides a unified interface
for parsing, normalization, and AST access.
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
    pass


class UniversalParser(BaseParser):
    """
    Universal SQL parser supporting multiple database dialects.
    """

    supported_dialects: tuple[str, ...] = (
        "postgresql", "postgres", "mysql", "mariadb", "sqlite",
        "mssql", "tsql", "oracle", "bigquery", "snowflake",
        "redshift", "clickhouse", "duckdb", "presto", "trino",
        "spark", "databricks", "hive", "teradata"
    )

    # Mapping of dialect aliases to sqlglot dialect names
    _DIALECT_MAP: dict[str, str] = {
        "postgresql": "postgres", "postgres": "postgres",
        "mysql": "mysql", "mariadb": "mysql",
        "sqlite": "sqlite",
        "mssql": "tsql", "tsql": "tsql", "sqlserver": "tsql",
        "oracle": "oracle",
        "bigquery": "bigquery",
        "snowflake": "snowflake",
        "redshift": "redshift",
        "clickhouse": "clickhouse",
        "duckdb": "duckdb",
        "presto": "presto", "trino": "trino",
        "spark": "spark", "databricks": "databricks",
        "hive": "hive"
    }

    # Patterns for dialect detection
    _DIALECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("postgres", re.compile(r"\$\d+", re.IGNORECASE)),
        ("postgres", re.compile(r"::\s*\w+", re.IGNORECASE)),
        ("mysql", re.compile(r"`\w+`")),
        ("tsql", re.compile(r"\bTOP\s+\d+", re.IGNORECASE)),
        ("tsql", re.compile(r"\[\w+\]")),
        ("oracle", re.compile(r"\bROWNUM\b", re.IGNORECASE)),
        ("bigquery", re.compile(r"`[\w-]+\.[\w-]+\.[\w-]+`")),
        ("snowflake", re.compile(r"\bFLATTEN\s*\(", re.IGNORECASE)),
    ]

    def __init__(self, dialect: str | None = None) -> None:
        self.dialect = dialect
        if dialect is not None and dialect.lower() not in self._DIALECT_MAP:
            raise UnsupportedDialectError(dialect)

    def parse(self, sql: str, *, dialect: str | None = None, file_path: str | None = None) -> list[Query]:
        effective_dialect = dialect or self.dialect
        if effective_dialect is None:
            effective_dialect = self.detect_dialect(sql)

        sqlglot_dialect = self._get_sqlglot_dialect(effective_dialect)
        statements = self._split_statements(sql)
        queries: list[Query] = []

        for idx, (statement_sql, line_offset, col_offset) in enumerate(statements):
            if not statement_sql.strip():
                continue

            try:
                parsed = sqlglot.parse_one(
                    statement_sql,
                    dialect=sqlglot_dialect,
                    error_level=sqlglot.ErrorLevel.WARN,
                )

                location = Location(
                    line=line_offset + 1,
                    column=col_offset + 1,
                    file=file_path,
                    query_index=idx,
                )

                tables = self._extract_tables_from_ast(parsed)
                columns = self._extract_columns_from_ast(parsed)
                query_type = self._get_query_type_from_ast(parsed)
                normalized = self._normalize_ast(parsed, sqlglot_dialect)

                queries.append(Query(
                    raw=statement_sql,
                    normalized=normalized,
                    dialect=effective_dialect or "unknown",
                    location=location,
                    ast=parsed,
                    tables=tuple(tables),
                    columns=tuple(columns),
                    query_type=query_type,
                ))

            except SqlglotParseError as e:
                # Log error but don't crash whole batch if possible
                raise ParseError(f"Failed to parse SQL", sql=statement_sql, details=str(e)) from e

        return queries

    def parse_single(self, sql: str, *, dialect: str | None = None, file_path: str | None = None) -> Query:
        queries = self.parse(sql, dialect=dialect, file_path=file_path)
        if len(queries) == 0: raise ParseError("No SQL statement found", sql=sql)
        if len(queries) > 1: raise ParseError(f"Expected single statement, found {len(queries)}", sql=sql)
        return queries[0]

    def detect_dialect(self, sql: str) -> str | None:
        dialect_scores: dict[str, int] = {}
        for dialect, pattern in self._DIALECT_PATTERNS:
            if pattern.search(sql):
                dialect_scores[dialect] = dialect_scores.get(dialect, 0) + 1
        
        if not dialect_scores:
            return None
            
        # Return dialect with highest score
        return max(dialect_scores, key=dialect_scores.get) # type: ignore

    def normalize(self, sql: str, *, dialect: str | None = None) -> str:
        sqlglot_dialect = self._get_sqlglot_dialect(dialect or self.dialect)
        try:
            parsed = sqlglot.parse_one(sql, dialect=sqlglot_dialect)
            return self._normalize_ast(parsed, sqlglot_dialect)
        except SqlglotParseError:
            return " ".join(sql.split())

    def extract_tables(self, sql: str, *, dialect: str | None = None) -> list[str]:
        sqlglot_dialect = self._get_sqlglot_dialect(dialect or self.dialect)
        try:
            parsed = sqlglot.parse_one(sql, dialect=sqlglot_dialect)
            return self._extract_tables_from_ast(parsed)
        except SqlglotParseError:
            return []

    def extract_columns(self, sql: str, *, dialect: str | None = None) -> list[str]:
        sqlglot_dialect = self._get_sqlglot_dialect(dialect or self.dialect)
        try:
            parsed = sqlglot.parse_one(sql, dialect=sqlglot_dialect)
            return self._extract_columns_from_ast(parsed)
        except SqlglotParseError:
            return []

    def get_query_type(self, sql: str) -> str | None:
        sql_stripped = sql.strip().upper()
        # Fast path
        first_word = sql_stripped.split()[0] if sql_stripped else ""
        if first_word in ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "DROP", "ALTER"):
            if first_word == "WITH": return "SELECT"
            return first_word
        return None

    def _get_sqlglot_dialect(self, dialect: str | None) -> str | None:
        return self._DIALECT_MAP.get(dialect.lower()) if dialect else None

    def _split_statements(self, sql: str) -> list[tuple[str, int, int]]:
        statements = []
        current_pos = 0
        try:
            parsed_statements = sqlglot.parse(sql)
            for stmt in parsed_statements:
                if not stmt: continue
                stmt_sql = stmt.sql()
                stmt_start = sql.find(stmt_sql.split()[0], current_pos) if stmt_sql.strip() else -1
                if stmt_start == -1: stmt_start = current_pos
                
                prefix = sql[:stmt_start]
                line_offset = prefix.count("\n")
                last_newline = prefix.rfind("\n")
                col_offset = stmt_start - last_newline - 1 if last_newline >= 0 else stmt_start
                
                statements.append((stmt_sql, line_offset, col_offset))
                current_pos = stmt_start + len(stmt_sql)
        except SqlglotParseError:
            # Fallback
            for part in sql.split(";"):
                if part.strip(): statements.append((part.strip(), 0, 0))
        return statements

    def _extract_tables_from_ast(self, ast: exp.Expression) -> list[str]:
        tables = []
        for table in ast.find_all(exp.Table):
            name = table.name
            if table.db: name = f"{table.db}.{name}"
            if name and name not in tables: tables.append(name)
        return tables

    def _extract_columns_from_ast(self, ast: exp.Expression) -> list[str]:
        columns = []
        for column in ast.find_all(exp.Column):
            name = column.name
            if column.table: name = f"{column.table}.{name}"
            if name and name not in columns: columns.append(name)
        return columns

    def _get_query_type_from_ast(self, ast: exp.Expression) -> str | None:
        """
        Safe determination of query type avoiding version conflicts.
        """
        if isinstance(ast, exp.Select): return "SELECT"
        if isinstance(ast, exp.Insert): return "INSERT"
        if isinstance(ast, exp.Update): return "UPDATE"
        if isinstance(ast, exp.Delete): return "DELETE"
        if isinstance(ast, exp.Merge): return "MERGE"
        if isinstance(ast, exp.Create): return "CREATE"
        if isinstance(ast, exp.Alter): return "ALTER"
        if isinstance(ast, exp.Drop): return "DROP"
        if isinstance(ast, exp.Grant): return "GRANT"
        
        # Check for Truncate safely (name changed in recent sqlglot versions)
        if hasattr(exp, "Truncate") and isinstance(ast, getattr(exp, "Truncate")):
            return "TRUNCATE"
        if hasattr(exp, "TruncateTable") and isinstance(ast, getattr(exp, "TruncateTable")):
            return "TRUNCATE"
            
        # Fallback for Commands
        if isinstance(ast, exp.Command):
            match = re.match(r"^\s*(\w+)", ast.sql())
            if match: return match.group(1).upper()

        return ast.__class__.__name__.upper()

    def _normalize_ast(self, ast: exp.Expression, dialect: str | None) -> str:
        return ast.sql(dialect=dialect, normalize=True, pretty=False)