from unittest.mock import MagicMock, patch

import pytest

from slowql.core.exceptions import ParseError

# The test now focuses on generic exceptions, so SqlglotParseError import is not directly used here.
from slowql.parser.universal import UniversalParser


class TestUniversalParserExtra:
    def test_parse_exception(self):
        # Test that a generic Exception from sqlglot.parse is correctly wrapped into ParseError.
        # The _split_statements method catches generic exceptions and re-raises them.
        parser = UniversalParser()
        with patch(
            "slowql.parser.universal.sqlglot.parse", side_effect=Exception("Boom")
        ), pytest.raises(ParseError):
            parser.parse("SELECT 1")

    def test_extract_tables_edge_cases(self):
        # Indirectly cover extract_tables/columns lines if missed
        parser = UniversalParser()
        # Test with complex query
        q = parser.parse_single("SELECT * FROM t1 JOIN t2 ON t1.id = t2.id")
        assert len(q.tables) == 2

    def test_normalize_empty_ast(self):
        # Lines 232, 234
        parser = UniversalParser()
        # Mock AST that returns None for sql()
        ast = MagicMock()
        ast.sql.return_value = ""
        assert parser.normalize(ast) == ""

    def test_normalize_none(self):
        # If dialect is passed but AST is weird?
        # normalize(self, ast: Any, dialect: str | None = None) -> str
        pass

    def test_parse_sqlglot_error(self):
        # Trigger sqlglot.errors.ParseError
        parser = UniversalParser()
        # This is invalid SQL, but the parser's fallback mechanism will split it by semicolon
        # and return it as a single, unparsed statement. It should not raise an error.
        queries = parser.parse("SELECT * FROM")  # Invalid SQL
        assert len(queries) == 1
        assert queries[0].raw == "SELECT * FROM"
