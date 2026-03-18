
import pytest

from slowql.core.exceptions import ParseError, UnsupportedDialectError
from slowql.parser.universal import UniversalParser


def test_universal_parser_init():
    parser = UniversalParser(dialect="postgresql")
    assert parser.default_dialect == "postgres"

    # Aliases
    parser2 = UniversalParser(dialect="postgres")
    assert parser2.default_dialect == "postgres"

    with pytest.raises(UnsupportedDialectError):
        UniversalParser(dialect="invalid_dialect")

def test_universal_parser_parse_basic():
    parser = UniversalParser()
    queries = parser.parse("SELECT * FROM users; DELETE FROM orders;")
    assert len(queries) == 2
    assert queries[0].query_type == "SELECT"
    assert queries[1].query_type == "DELETE"
    assert "users" in queries[0].tables
    assert "orders" in queries[1].tables

def test_universal_parser_parse_single():
    parser = UniversalParser()
    query = parser.parse_single("SELECT * FROM users")
    assert query.query_type == "SELECT"

    # Empty
    with pytest.raises(ParseError):
        parser.parse_single("   -- just a comment  ")

    # Multiple
    with pytest.raises(ParseError):
        parser.parse_single("SELECT 1; SELECT 2;")

def test_universal_parser_detect_dialect():
    parser = UniversalParser()
    assert parser.detect_dialect("SELECT `id` FROM `users`") == "mysql"
    assert parser.detect_dialect("SELECT top 10 [id] FROM [users]") == "tsql"
    assert parser.detect_dialect("SELECT * FROM table WHERE col::int = 1") == "postgres"
    # The regex for bigquery looks for backticks: `dataset.table`
    assert parser.detect_dialect("SELECT * FROM `dataset`.`table` LIMIT 10") == "bigquery"

def test_universal_parser_extractors():
    parser = UniversalParser()
    tables = parser.extract_tables("SELECT a FROM t1 JOIN t2 ON t1.id = t2.id")
    assert "t1" in tables
    assert "t2" in tables

    cols = parser.extract_columns("SELECT id, name FROM users WHERE status = 1")
    assert "id" in cols
    assert "name" in cols
    assert "status" in cols

def test_universal_parser_get_query_type():
    parser = UniversalParser()
    assert parser.get_query_type("   select * from t") == "SELECT"
    assert parser.get_query_type("WITH cte AS (...) SELECT * FROM cte") == "SELECT"
    assert parser.get_query_type("INSERT INTO t VALUES (1)") == "INSERT"
    assert parser.get_query_type("SOME_UNKNOWN_CMD") is None

def test_universal_parser_normalize_fallback():
    parser = UniversalParser()
    # Provide a string that fails sqlglot parsing to trigger the fallback
    # Usually sqlglot is very forgiving, but a clear syntax error helps
    norm = parser.normalize("SELECT FROM WHERE ; ; ;")
    assert isinstance(norm, str)

    # Test with None ast
    assert parser.normalize(None) == ""

def test_universal_parser_unsupported_type_fallback():
    parser = UniversalParser()
    # Test the fallback in _get_query_type_from_ast
    # A raw sqlglot expression that isn't mapped
    from sqlglot import exp
    ast = exp.Hint(expressions=[])
    q_type = parser._get_query_type_from_ast(ast)
    assert q_type == "HINT"

def test_universal_parser_parse_error():
    parser = UniversalParser()
    # Give it something that the source splitter passes but sqlglot strictly rejects
    # We might need to mock to guarantee ParseError from the parser wrapper
    from unittest.mock import patch
    with patch("slowql.parser.source_splitter.SourceSplitter.split", side_effect=Exception("Split failed")), pytest.raises(ParseError):
        parser.parse("SELECT 1")
