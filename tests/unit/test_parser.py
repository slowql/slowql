# tests/unit/test_parser.py
"""
Test parser classes.
"""

from slowql.core.models import Query
from slowql.parser.base import BaseParser
from slowql.parser.tokenizer import Tokenizer
from slowql.parser.universal import UniversalParser


class TestBaseParser:
    def test_base_parser_is_abstract(self):
        # BaseParser is abstract
        try:
            BaseParser()
            raise AssertionError("Should not be able to instantiate abstract class")
        except TypeError:
            pass


class TestTokenizer:
    def test_tokenizer_creation(self):
        tokenizer = Tokenizer()
        assert tokenizer is not None

    def test_tokenizer_tokenize(self):
        tokenizer = Tokenizer()
        sql = "SELECT * FROM users"
        tokens = tokenizer.tokenize(sql)
        assert hasattr(tokens, "__iter__")  # It's a generator
        tokens_list = list(tokens)
        assert len(tokens_list) > 0


class TestUniversalParser:
    def test_universal_parser_creation(self):
        parser = UniversalParser()
        assert parser is not None

    def test_universal_parser_parse(self):
        parser = UniversalParser()
        sql = "SELECT * FROM users WHERE id = 1"
        queries = parser.parse(sql)
        assert isinstance(queries, list)
        assert len(queries) > 0
        assert isinstance(queries[0], Query)

    def test_universal_parser_parse_multiple_statements(self):
        parser = UniversalParser()
        sql = "SELECT * FROM users; INSERT INTO logs VALUES (1, 'test');"
        queries = parser.parse(sql)
        assert isinstance(queries, list)
        assert len(queries) == 2

    def test_universal_parser_parse_with_location(self):
        parser = UniversalParser()
        sql = "SELECT * FROM users"
        queries = parser.parse(sql, file_path="test.sql")
        assert len(queries) > 0
        assert queries[0].location.file == "test.sql"

    def test_universal_parser_dialect_detection(self):
        parser = UniversalParser()
        # Test various SQL dialects
        mysql_sql = "SELECT * FROM users LIMIT 1"
        postgres_sql = "SELECT * FROM users LIMIT 1 OFFSET 5"

        queries1 = parser.parse(mysql_sql, dialect="mysql")
        queries2 = parser.parse(postgres_sql, dialect="postgres")

        assert len(queries1) > 0
        assert len(queries2) > 0
