from slowql.core.exceptions import (
    AnalysisError,
    ConfigurationError,
    ParseError,
    RuleNotFoundError,
    SlowQLError,
    UnsupportedDialectError,
)
from slowql.core.models import Location


class TestExceptionsCoverage:
    def test_slowql_error(self):
        e = SlowQLError("msg", details="det")
        assert "msg" in str(e)
        assert "Details: det" in str(e)

    def test_parse_error(self):
        loc = Location(1, 1)
        e = ParseError("msg", sql="SELECT *", location=loc, details="det")
        s = str(e)
        assert "at line 1, column 1" in s
        assert "SQL: SELECT *" in s
        assert "Details: det" in s

        e2 = ParseError("msg", sql="x" * 150)
        assert "..." in str(e2)  # Truncation check

    def test_analysis_error(self):
        e = AnalysisError("msg", analyzer_name="ana", rule_id="rl", details="det")
        s = str(e)
        assert "Analyzer: ana" in s
        assert "Rule: rl" in s
        assert "Details: det" in s

    def test_configuration_error(self):
        e = ConfigurationError("msg", config_key="k", config_value="v", details="det")
        s = str(e)
        assert "Key: k" in s
        assert "Value: 'v'" in s
        assert "Details: det" in s

    def test_rule_not_found_error_suggestions(self):
        # Case with suggestions
        e = RuleNotFoundError("SEC-001", available_rules=["SEC-002", "PERF-001"])
        s = str(e)
        assert "Did you mean: SEC-002" in s

        # Case without suggestions
        e2 = RuleNotFoundError("UNK-001", available_rules=["SEC-001"])
        assert "Did you mean" not in str(e2)

    def test_unsupported_dialect_error(self):
        e = UnsupportedDialectError("foo")
        s = str(e)
        assert "Unsupported SQL dialect: foo" in s
        assert "Supported dialects:" in s
