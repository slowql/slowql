# slowql/tests/unit/test_plugins_yaml.py
"""Unit tests for the YAML rule loader."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from slowql.core.models import Dimension, Severity
from slowql.plugins.yaml_loader import YAMLRuleLoader

VALID_YAML = dedent("""\
    rules:
      - id: "CUSTOM-001"
        name: "No DELETE on billing"
        description: "DELETE on billing schema is forbidden."
        dimension: "security"
        severity: "critical"
        pattern: "(?i)DELETE\\\\s+FROM\\\\s+billing\\\\."
        message: "DELETE operation forbidden on billing schema."

      - id: "CUSTOM-002"
        name: "All tables need created_at"
        description: "Every table must have created_at."
        dimension: "quality"
        severity: "medium"
        pattern: "(?i)CREATE\\\\s+TABLE"
        message: "Table is missing created_at column."
""")


class TestYAMLRuleLoaderFromString:
    def test_loads_valid_yaml_string(self) -> None:
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        assert len(rules) == 2

    def test_rule_ids_are_correct(self) -> None:
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        ids = {r.id for r in rules}
        assert "CUSTOM-001" in ids
        assert "CUSTOM-002" in ids

    def test_rule_severity_mapping(self) -> None:
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        rule = next(r for r in rules if r.id == "CUSTOM-001")
        assert rule.severity == Severity.CRITICAL

    def test_rule_dimension_mapping(self) -> None:
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        rule = next(r for r in rules if r.id == "CUSTOM-002")
        assert rule.dimension == Dimension.QUALITY

    def test_rules_are_pattern_rules(self) -> None:
        from slowql.rules.base import PatternRule
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        for rule in rules:
            assert isinstance(rule, PatternRule)

    def test_pattern_rule_fires_on_matching_sql(self) -> None:
        from slowql.core.models import Location, Query
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        rule = next(r for r in rules if r.id == "CUSTOM-001")
        query = Query(
            raw="DELETE FROM billing.orders WHERE id = 1",
            normalized="DELETE FROM billing.orders WHERE id = 1",
            dialect="postgresql",
            location=Location(line=1, column=1, file="test.sql"),
        )
        issues = rule.check(query)
        assert len(issues) >= 1
        assert issues[0].rule_id == "CUSTOM-001"

    def test_pattern_rule_does_not_fire_on_non_matching_sql(self) -> None:
        from slowql.core.models import Location, Query
        rules = YAMLRuleLoader.load_from_string(VALID_YAML)
        rule = next(r for r in rules if r.id == "CUSTOM-001")
        query = Query(
            raw="SELECT * FROM orders",
            normalized="SELECT * FROM orders",
            dialect="postgresql",
            location=Location(line=1, column=1, file="test.sql"),
        )
        issues = rule.check(query)
        assert issues == []

    def test_empty_rules_list_returns_empty(self) -> None:
        yaml_content = "rules: []\n"
        rules = YAMLRuleLoader.load_from_string(yaml_content)
        assert rules == []

    def test_missing_rules_key_returns_empty(self) -> None:
        rules = YAMLRuleLoader.load_from_string("something_else: 123\n")
        assert rules == []


class TestYAMLRuleLoaderValidation:
    def test_missing_id_raises_error(self) -> None:
        yaml_content = dedent("""\
            rules:
              - name: "No id here"
                description: "."
                dimension: "security"
                severity: "low"
                pattern: "x"
                message: "x"
        """)
        with pytest.raises(ValueError, match="id"):
            YAMLRuleLoader.load_from_string(yaml_content)

    def test_missing_pattern_raises_error(self) -> None:
        yaml_content = dedent("""\
            rules:
              - id: "CUSTOM-BAD-001"
                name: "No pattern"
                description: "."
                dimension: "security"
                severity: "low"
                message: "x"
        """)
        with pytest.raises(ValueError, match="pattern"):
            YAMLRuleLoader.load_from_string(yaml_content)

    def test_invalid_severity_raises_error(self) -> None:
        yaml_content = dedent("""\
            rules:
              - id: "CUSTOM-BAD-002"
                name: "Bad severity"
                description: "."
                dimension: "security"
                severity: "extreme"
                pattern: "x"
                message: "x"
        """)
        with pytest.raises(ValueError, match="severity"):
            YAMLRuleLoader.load_from_string(yaml_content)

    def test_invalid_dimension_raises_error(self) -> None:
        yaml_content = dedent("""\
            rules:
              - id: "CUSTOM-BAD-003"
                name: "Bad dimension"
                description: "."
                dimension: "unknown_dim"
                severity: "low"
                pattern: "x"
                message: "x"
        """)
        with pytest.raises(ValueError, match="dimension"):
            YAMLRuleLoader.load_from_string(yaml_content)


class TestYAMLRuleLoaderFromFile:
    def test_loads_from_yml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "my_rules.yml"
        f.write_text(VALID_YAML)
        rules = YAMLRuleLoader.load_from_file(f)
        assert len(rules) == 2

    def test_loads_from_yaml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "my_rules.yaml"
        f.write_text(VALID_YAML)
        rules = YAMLRuleLoader.load_from_file(f)
        assert len(rules) == 2

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            YAMLRuleLoader.load_from_file(Path("/nonexistent/rules.yml"))
