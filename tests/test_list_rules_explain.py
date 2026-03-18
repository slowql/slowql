"""Tests for --list-rules and --explain CLI commands."""
from __future__ import annotations

from slowql.cli.app import _cmd_explain, _cmd_list_rules


class TestCmdListRules:
    def test_returns_zero(self) -> None:
        assert _cmd_list_rules() == 0

    def test_filter_dimension(self) -> None:
        assert _cmd_list_rules(dimension="security") == 0

    def test_filter_dialect(self) -> None:
        assert _cmd_list_rules(dialect="postgresql") == 0

    def test_no_match_filter(self) -> None:
        assert _cmd_list_rules(dimension="security", dialect="sqlite") == 0

    def test_all_rules_shown(self, capsys) -> None:
        _cmd_list_rules()
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) >= 270

    def test_dimension_filter_reduces_results(self, capsys) -> None:
        from slowql.rules.catalog import get_all_rules
        all_rules = get_all_rules()
        sec_rules = [r for r in all_rules if r.dimension.value == "security"]
        assert len(sec_rules) < len(all_rules)


class TestCmdExplain:
    def test_known_rule_returns_zero(self) -> None:
        assert _cmd_explain("PERF-SCAN-001") == 0

    def test_case_insensitive(self) -> None:
        assert _cmd_explain("perf-scan-001") == 0

    def test_unknown_rule_returns_one(self) -> None:
        assert _cmd_explain("FAKE-RULE-999") == 1

    def test_security_rule(self) -> None:
        assert _cmd_explain("SEC-INJ-001") == 0

    def test_dialect_specific_rule(self) -> None:
        assert _cmd_explain("COST-BQ-001") == 0
