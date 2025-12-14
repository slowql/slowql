# tests/unit/test_exceptions.py
"""
Test exception classes.
"""

import pytest
from slowql.core.exceptions import (
    SlowQLError, ParseError, FileNotFoundError, AnalysisError,
    ConfigurationError, RuleNotFoundError, UnsupportedDialectError
)


class TestSlowQLError:
    def test_slowql_error_creation(self):
        error = SlowQLError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"

    def test_slowql_error_with_details(self):
        error = SlowQLError("Test error", details="More info")
        assert error.details == "More info"


class TestParseError:
    def test_parse_error_creation(self):
        error = ParseError("Parse failed")
        assert str(error) == "Parse failed"
        assert isinstance(error, SlowQLError)

    def test_parse_error_with_sql(self):
        error = ParseError("Parse failed", sql="SELECT *")
        assert error.sql == "SELECT *"


class TestFileNotFoundError:
    def test_file_not_found_error_creation(self):
        error = FileNotFoundError("file.sql")
        assert str(error) == "File not found: file.sql"
        assert error.path == "file.sql"
        assert isinstance(error, SlowQLError)


class TestAnalysisError:
    def test_analysis_error_creation(self):
        error = AnalysisError("Analysis failed")
        assert str(error) == "Analysis failed"
        assert isinstance(error, SlowQLError)

    def test_analysis_error_with_rule(self):
        error = AnalysisError("Analysis failed", rule_id="TEST-001")
        assert error.rule_id == "TEST-001"


class TestConfigurationError:
    def test_configuration_error_creation(self):
        error = ConfigurationError("Config error")
        assert str(error) == "Config error"
        assert isinstance(error, SlowQLError)

    def test_configuration_error_with_key(self):
        error = ConfigurationError("Config error", config_key="database.host")
        assert error.config_key == "database.host"


class TestRuleNotFoundError:
    def test_rule_not_found_error_creation(self):
        error = RuleNotFoundError("TEST-001")
        assert str(error) == "Rule not found: TEST-001"
        assert error.rule_id == "TEST-001"
        assert isinstance(error, SlowQLError)

    def test_rule_not_found_error_with_suggestions(self):
        error = RuleNotFoundError("SEC-001", available_rules=["SEC-002", "SEC-003"])
        assert "SEC-001" in str(error)


class TestUnsupportedDialectError:
    def test_unsupported_dialect_error_creation(self):
        error = UnsupportedDialectError("unknown")
        assert "Unsupported SQL dialect: unknown" in str(error)
        assert error.dialect == "unknown"
        assert isinstance(error, SlowQLError)
        assert "mysql" in error.supported_dialects