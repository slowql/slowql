
import pytest
from unittest.mock import MagicMock, patch
from slowql.parser.universal import UniversalParser
from slowql.core.exceptions import ParseError
from slowql.core.models import Query

class TestUniversalParserExtra:
    def test_parse_exception(self):
        # Line 84 coverage: Exception handling in parse
        parser = UniversalParser()
        with patch("slowql.parser.universal.sqlglot.parse", side_effect=Exception("Boom")):
            # It should catch generic exception and maybe return empty or raise ParseError?
            # It raises ParseError (wrapped).
            with pytest.raises(ParseError):
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
         parser = UniversalParser()
         # If dialect is passed but AST is weird?
         # normalize(self, ast: Any, dialect: str | None = None) -> str
         pass

    def test_parse_sqlglot_error(self):
        # Trigger sqlglot.errors.ParseError
        parser = UniversalParser()
        with pytest.raises(ParseError):
            parser.parse("SELECT * FROM") # Invalid SQL

