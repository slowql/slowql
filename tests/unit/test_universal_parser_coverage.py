"""Targeted coverage tests for parser/universal.py uncovered lines."""
from __future__ import annotations

import pytest

from slowql.core.exceptions import UnsupportedDialectError
from slowql.parser.universal import UniversalParser


def test_unsupported_dialect_raises():
    """Covers: UnsupportedDialectError raise branch."""
    with pytest.raises(UnsupportedDialectError):
        UniversalParser(dialect="notarealdialect12345")


def test_mssql_alias_normalized():
    """Covers: elif dialect == 'mssql': dialect = 'tsql' branch."""
    parser = UniversalParser(dialect="mssql")
    assert parser.default_dialect == "tsql"


def test_postgresql_alias_normalized():
    """Covers: if dialect == 'postgresql': dialect = 'postgres' branch."""
    parser = UniversalParser(dialect="postgresql")
    assert parser.default_dialect == "postgres"


def test_parse_with_mssql_dialect_in_parse_call():
    """Covers: dialect normalization inside parse() method."""
    parser = UniversalParser()
    queries = parser.parse("SELECT 1", dialect="postgresql")
    assert len(queries) >= 1


def test_parse_empty_sql_returns_empty():
    """Covers: empty parse result handling."""
    parser = UniversalParser()
    queries = parser.parse("", dialect="postgresql")
    assert isinstance(queries, list)


def test_parse_multiple_statements():
    """Covers: multiple statement iteration."""
    parser = UniversalParser()
    queries = parser.parse(
        "SELECT 1; SELECT 2; SELECT 3;",
        dialect="postgresql"
    )
    assert len(queries) >= 2


def test_detect_dialect_returns_string():
    """Covers: detect_dialect method."""
    parser = UniversalParser()
    result = parser.detect_dialect("SELECT TOP 10 * FROM users")
    assert isinstance(result, str)


def test_normalize_with_ast():
    """Covers: normalize() method with AST input."""
    import sqlglot
    parser = UniversalParser()
    ast = sqlglot.parse_one("SELECT * FROM users")
    result = parser.normalize(ast)
    assert isinstance(result, str)
    assert "SELECT" in result.upper()


def test_normalize_with_string():
    """Covers: normalize() with string input branch."""
    parser = UniversalParser()
    result = parser.normalize("SELECT * FROM users")
    assert isinstance(result, str)
