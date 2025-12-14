
import pytest
import re
from unittest.mock import MagicMock, patch
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from slowql.parser.universal import UniversalParser
from slowql.core.exceptions import ParseError, UnsupportedDialectError

class TestUniversalParserCoverage:
    def test_unsupported_dialect_init(self):
        with pytest.raises(UnsupportedDialectError):
            UniversalParser(dialect="invalid_dialect")

    def test_parse_single_no_statement(self):
        parser = UniversalParser()
        with pytest.raises(ParseError, match="No SQL statement found"):
            parser.parse_single("")
            
        with pytest.raises(ParseError, match="No SQL statement found"):
            parser.parse_single("   ")
            
        with pytest.raises(ParseError, match="No SQL statement found"):
            parser.parse_single("-- just a comment")

    def test_parse_single_multiple_statements(self):
        parser = UniversalParser()
        with pytest.raises(ParseError, match="Expected single statement"):
            parser.parse_single("SELECT 1; SELECT 2")

    def test_parse_error_handling(self):
        parser = UniversalParser()
        # Mock sqlglot.parse_one to raise SqlglotParseError
        with patch("sqlglot.parse_one", side_effect=SqlglotParseError("test error")):
            with pytest.raises(ParseError, match="Failed to parse SQL"):
                parser.parse("SELECT * FROM t")

    def test_detect_dialect(self):
        parser = UniversalParser()
        
        # Test postgres detection
        assert parser.detect_dialect("SELECT $1") == "postgres"
        assert parser.detect_dialect("SELECT col::text") == "postgres"
        
        # Test mysql detection
        assert parser.detect_dialect("SELECT `col`") == "mysql"
        
        # Test tsql detection
        assert parser.detect_dialect("SELECT TOP 10 *") == "tsql"
        assert parser.detect_dialect("SELECT [col]") == "tsql"
        
        # Test oracle detection
        assert parser.detect_dialect("SELECT * FROM t WHERE ROWNUM <= 1") == "oracle"
        
        # Test bigquery detection
        assert parser.detect_dialect("SELECT * FROM `p.d.t`") == "bigquery"
        
        # Test snowflake detection
        assert parser.detect_dialect("SELECT * FROM t, LATERAL FLATTEN(input => col)") == "snowflake"
        
        # Test multiple matches (should pick highest score)
        # "TOP 10" is tsql (1 match), "::" is postgres (1 match).
        # This specific test case might be ambiguous depending on exact impl, 
        # but let's try to bias it.
        # "SELECT TOP 10 [col]" -> 2 matches for tsql
        assert parser.detect_dialect("SELECT TOP 10 [col]") == "tsql"

        # No match
        assert parser.detect_dialect("SELECT * FROM t") is None

    def test_normalize_error(self):
        parser = UniversalParser()
        with patch("sqlglot.parse_one", side_effect=SqlglotParseError("err")):
             # Should fallback to basic whitespace normalization
             assert parser.normalize("SELECT  *   FROM   t") == "SELECT * FROM t"

    def test_extract_tables_error(self):
        parser = UniversalParser()
        with patch("sqlglot.parse_one", side_effect=SqlglotParseError("err")):
            assert parser.extract_tables("bad sql") == []

    def test_extract_columns_error(self):
        parser = UniversalParser()
        with patch("sqlglot.parse_one", side_effect=SqlglotParseError("err")):
            assert parser.extract_columns("bad sql") == []

    def test_get_query_type_fast_path(self):
        parser = UniversalParser()
        assert parser.get_query_type("SELECT *") == "SELECT"
        assert parser.get_query_type("WITH t AS (SELECT 1) SELECT *") == "SELECT"
        assert parser.get_query_type("INSERT INTO t VALUES (1)") == "INSERT"
        assert parser.get_query_type("garbage") is None
        assert parser.get_query_type("") is None

    def test_split_statements_ast_fail_fallback(self):
        parser = UniversalParser()
        # Mock sqlglot.parse to raise error, forcing fallback to semicolon split
        with patch("sqlglot.parse", side_effect=SqlglotParseError("err")):
            stmts = parser._split_statements("SELECT 1; SELECT 2")
            assert len(stmts) == 2
            assert stmts[0][0] == "SELECT 1"
            assert stmts[1][0] == "SELECT 2"

    def test_get_query_type_from_ast_coverage(self):
        parser = UniversalParser()
        
        # We can construct sqlglot expressions purely for testing logic mapping
        assert parser._get_query_type_from_ast(exp.Select()) == "SELECT"
        assert parser._get_query_type_from_ast(exp.Insert()) == "INSERT"
        assert parser._get_query_type_from_ast(exp.Update()) == "UPDATE"
        assert parser._get_query_type_from_ast(exp.Delete()) == "DELETE"
        # exp.Merge might need args depending on version, usually pure init works
        assert parser._get_query_type_from_ast(exp.Merge()) == "MERGE"
        assert parser._get_query_type_from_ast(exp.Create()) == "CREATE"
        assert parser._get_query_type_from_ast(exp.Alter()) == "ALTER"
        assert parser._get_query_type_from_ast(exp.Drop()) == "DROP"
        # Grant might not be in all versions, checking safely or assuming it exists if imported
        if hasattr(exp, "Grant"):
            assert parser._get_query_type_from_ast(exp.Grant()) == "GRANT"
        
        # Test Command fallback
        cmd = exp.Command()
        cmd.set("this", "VACUUM ANALYZE")
        assert parser._get_query_type_from_ast(cmd) == "VACUUM"
        
        # Test Default fallback
        class UnknownExp(exp.Expression):
            pass
        assert parser._get_query_type_from_ast(UnknownExp()) == "UNKNOWNEXP"

