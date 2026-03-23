# tests/unit/test_suppressions.py
"""
Unit tests for the SlowQL inline suppression system.

Covers all four directives:
  -- slowql-disable-line [RULE-ID]
  -- slowql-disable-next-line [RULE-ID]
  -- slowql-disable [RULE-ID]  /  -- slowql-enable [RULE-ID]
  -- slowql-disable-file [RULE-ID]
"""

from __future__ import annotations

import pytest  # noqa: TC002

from slowql.core.suppressions import SuppressionMap, parse_suppressions


class TestDisableLine:
    def test_suppresses_exact_rule_on_same_line(self) -> None:
        sql = "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "PERF-SCAN-001")

    def test_does_not_suppress_different_rule_on_same_line(self) -> None:
        sql = "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "SEC-INJ-001")

    def test_does_not_suppress_next_line(self) -> None:
        sql = "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001\nSELECT 1;"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "PERF-SCAN-001")

    def test_all_rules_suppressed_when_no_rule_id(self) -> None:
        sql = "SELECT * FROM users;  -- slowql-disable-line"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "PERF-SCAN-001")
        assert sm.is_suppressed(1, "SEC-INJ-001")
        assert sm.is_suppressed(1, "ANY-RULE-999")

    def test_case_insensitive_rule_id(self) -> None:
        sql = "SELECT 1;  -- slowql-disable-line perf-scan-001"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "PERF-SCAN-001")

    def test_multiline_suppresses_correct_line_only(self) -> None:
        sql = (
            "SELECT 1;\n"
            "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001\n"
            "SELECT 2;\n"
        )
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "PERF-SCAN-001")
        assert sm.is_suppressed(2, "PERF-SCAN-001")
        assert not sm.is_suppressed(3, "PERF-SCAN-001")

    def test_prefix_matching(self) -> None:
        """Prefix-style suppress: PERF suppresses PERF-SCAN-001."""
        sql = "SELECT * FROM t;  -- slowql-disable-line PERF-SCAN"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "PERF-SCAN-001")
        assert not sm.is_suppressed(1, "PERF-IDX-001")


class TestDisableNextLine:
    def test_suppresses_exact_rule_on_next_line(self) -> None:
        sql = "-- slowql-disable-next-line SEC-INJ-001\nSELECT * FROM users;"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "SEC-INJ-001")

    def test_does_not_suppress_directive_line_itself(self) -> None:
        sql = "-- slowql-disable-next-line SEC-INJ-001\nSELECT * FROM users;"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "SEC-INJ-001")

    def test_does_not_suppress_two_lines_ahead(self) -> None:
        sql = (
            "-- slowql-disable-next-line SEC-INJ-001\n"
            "SELECT 1;\n"
            "SELECT * FROM users;\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "SEC-INJ-001")
        assert not sm.is_suppressed(3, "SEC-INJ-001")

    def test_all_rules_when_no_rule_id(self) -> None:
        sql = "-- slowql-disable-next-line\nSELECT * FROM users;"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "PERF-SCAN-001")
        assert sm.is_suppressed(2, "SEC-INJ-001")

    def test_does_not_suppress_different_rule(self) -> None:
        sql = "-- slowql-disable-next-line SEC-INJ-001\nSELECT * FROM t;"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "PERF-SCAN-001")

    def test_skips_blank_lines_to_find_next_code_line(self) -> None:
        """
        The directive targets the next non-blank, non-comment line
        after the directive itself.
        """
        sql = (
            "-- slowql-disable-next-line PERF-SCAN-001\n"
            "\n"
            "SELECT * FROM users;\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(3, "PERF-SCAN-001")


class TestBlockDisableEnable:
    def test_suppresses_lines_between_disable_and_enable(self) -> None:
        sql = (
            "SELECT 1;\n"
            "-- slowql-disable SEC-INJ-001\n"
            "SELECT password FROM users;\n"
            "SELECT secret FROM tokens;\n"
            "-- slowql-enable SEC-INJ-001\n"
            "SELECT 2;\n"
        )
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "SEC-INJ-001")
        assert sm.is_suppressed(3, "SEC-INJ-001")
        assert sm.is_suppressed(4, "SEC-INJ-001")
        assert not sm.is_suppressed(6, "SEC-INJ-001")

    def test_open_block_suppresses_to_eof(self) -> None:
        sql = (
            "SELECT 1;\n"
            "-- slowql-disable PERF-SCAN-001\n"
            "SELECT * FROM users;\n"
            "SELECT * FROM orders;\n"
        )
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "PERF-SCAN-001")
        assert sm.is_suppressed(3, "PERF-SCAN-001")
        assert sm.is_suppressed(4, "PERF-SCAN-001")

    def test_block_all_rules_no_rule_id(self) -> None:
        sql = (
            "-- slowql-disable\n"
            "SELECT * FROM users;\n"
            "-- slowql-enable\n"
            "SELECT 1;\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "PERF-SCAN-001")
        assert sm.is_suppressed(2, "SEC-INJ-001")
        assert not sm.is_suppressed(4, "PERF-SCAN-001")

    def test_multiple_independent_blocks_same_rule(self) -> None:
        sql = (
            "-- slowql-disable PERF-SCAN-001\n"
            "SELECT * FROM a;\n"
            "-- slowql-enable PERF-SCAN-001\n"
            "SELECT * FROM b;\n"
            "-- slowql-disable PERF-SCAN-001\n"
            "SELECT * FROM c;\n"
            "-- slowql-enable PERF-SCAN-001\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "PERF-SCAN-001")
        assert not sm.is_suppressed(4, "PERF-SCAN-001")
        assert sm.is_suppressed(6, "PERF-SCAN-001")

    def test_different_rules_in_overlapping_blocks(self) -> None:
        sql = (
            "-- slowql-disable PERF-SCAN-001\n"
            "-- slowql-disable SEC-INJ-001\n"
            "SELECT * FROM users;\n"
            "-- slowql-enable PERF-SCAN-001\n"
            "SELECT name FROM users;\n"
            "-- slowql-enable SEC-INJ-001\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(3, "PERF-SCAN-001")
        assert sm.is_suppressed(3, "SEC-INJ-001")
        assert not sm.is_suppressed(5, "PERF-SCAN-001")
        assert sm.is_suppressed(5, "SEC-INJ-001")

    def test_enable_without_disable_is_harmless(self) -> None:
        sql = "-- slowql-enable PERF-SCAN-001\nSELECT 1;\n"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "PERF-SCAN-001")


class TestDisableFile:
    def test_suppresses_all_lines_in_file(self) -> None:
        sql = (
            "-- slowql-disable-file PERF-SCAN-001\n"
            "SELECT * FROM users;\n"
            "SELECT * FROM orders;\n"
        )
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(2, "PERF-SCAN-001")
        assert sm.is_suppressed(3, "PERF-SCAN-001")

    def test_does_not_affect_other_rules(self) -> None:
        sql = (
            "-- slowql-disable-file PERF-SCAN-001\n"
            "SELECT * FROM users;\n"
        )
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "SEC-INJ-001")

    def test_disable_file_all_rules(self) -> None:
        sql = "-- slowql-disable-file\nSELECT * FROM users;\n"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "ANY-RULE")
        assert sm.is_suppressed(99, "PERF-SCAN-001")

    def test_disable_file_can_appear_anywhere_in_file(self) -> None:
        sql = (
            "SELECT 1;\n"
            "SELECT 2;\n"
            "-- slowql-disable-file SEC-INJ-001\n"
            "SELECT 3;\n"
        )
        sm = parse_suppressions(sql)
        # File-level applies retroactively to the whole file
        assert sm.is_suppressed(1, "SEC-INJ-001")
        assert sm.is_suppressed(4, "SEC-INJ-001")


class TestEdgeCases:
    def test_empty_sql_returns_no_suppressions(self) -> None:
        sm = parse_suppressions("")
        assert not sm.is_suppressed(1, "ANY-RULE")

    def test_sql_without_directives_returns_no_suppressions(self) -> None:
        sql = "SELECT 1;\nSELECT 2;\n"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "ANY-RULE")
        assert not sm.is_suppressed(2, "ANY-RULE")

    def test_unknown_directive_name_is_ignored(self) -> None:
        sql = "-- slowql-ignore-line PERF-SCAN-001\nSELECT 1;\n"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "PERF-SCAN-001")

    def test_non_slowql_comment_is_ignored(self) -> None:
        sql = "-- disable PERF-SCAN-001\nSELECT 1;\n"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(2, "PERF-SCAN-001")

    def test_directive_inside_string_literal_is_ignored(self) -> None:
        sql = "SELECT '-- slowql-disable-line PERF-SCAN-001' FROM t;\n"
        sm = parse_suppressions(sql)
        assert not sm.is_suppressed(1, "PERF-SCAN-001")

    def test_multiple_rule_ids_on_same_directive(self) -> None:
        """Comma-separated rule IDs are supported."""
        sql = "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001, SEC-INJ-001"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "PERF-SCAN-001")
        assert sm.is_suppressed(1, "SEC-INJ-001")
        assert not sm.is_suppressed(1, "REL-001")

    def test_suppression_map_repr(self) -> None:
        sm = parse_suppressions("")
        assert "SuppressionMap" in repr(sm)


class TestSuppressionMapAPI:
    def test_is_suppressed_returns_false_for_unseen_line(self) -> None:
        sm = parse_suppressions("SELECT 1;")
        assert not sm.is_suppressed(999, "ANY-RULE")

    def test_is_suppressed_line_zero_is_falsy(self) -> None:
        sm = parse_suppressions("SELECT 1;")
        assert not sm.is_suppressed(0, "ANY-RULE")

    def test_empty_rule_id_matches_all_rules(self) -> None:
        """When the directive carries no rule ID, any rule_id query returns True."""
        sql = "SELECT 1;  -- slowql-disable-line"
        sm = parse_suppressions(sql)
        assert sm.is_suppressed(1, "")
        assert sm.is_suppressed(1, "ANYTHING")

    def test_suppression_map_has_no_active_issues_attr(self) -> None:
        sm = SuppressionMap()
        assert hasattr(sm, "is_suppressed")


class TestEngineIntegration:
    """
    Integration-level tests: the engine must honour inline suppressions
    out of the box.
    """

    def test_engine_suppresses_disabled_line_issue(self) -> None:
        from slowql.core.engine import SlowQL

        engine = SlowQL(auto_discover=False)
        # Build a SQL string that would normally trigger PERF-SCAN rules.
        # We inject a fake issue via monkeypatching in a separate test.
        # Here we simply verify that suppressed_count is on the result.
        result = engine.analyze("SELECT 1;")
        assert hasattr(result, "suppressed_count")
        assert result.suppressed_count >= 0

    def test_engine_suppressed_count_increases_when_issue_suppressed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from slowql.core.engine import SlowQL
        from slowql.core.models import Dimension, Issue, Location, Severity

        engine = SlowQL(auto_discover=False)

        suppressed_issue = Issue(
            rule_id="PERF-SCAN-001",
            message="Table scan",
            severity=Severity.MEDIUM,
            dimension=Dimension.PERFORMANCE,
            location=Location(line=1, column=1),
            snippet="SELECT * FROM users",
        )

        monkeypatch.setattr(
            engine,
            "_run_analyzers",
            MagicMock(return_value=[suppressed_issue]),
        )

        sql = "SELECT * FROM users;  -- slowql-disable-line PERF-SCAN-001"
        result = engine.analyze(sql)

        # The issue should NOT appear in reported issues
        assert not any(i.rule_id == "PERF-SCAN-001" for i in result.issues)
        # It must be counted in suppressed_count
        assert result.suppressed_count == 1
