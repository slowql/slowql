# slowql/tests/integration/test_custom_rules.py
"""Integration tests for custom rule engine (Python plugins + YAML rules)."""

from __future__ import annotations

from textwrap import dedent
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from slowql.core.config import AnalysisConfig, Config, PluginConfig
from slowql.core.engine import SlowQL

BILLING_SQL = "DELETE FROM billing.orders WHERE id = 1;\n"
SAFE_SQL = "SELECT id FROM orders WHERE id = 1;\n"


def make_yaml_plugin(tmp_path: Path) -> Path:
    """Write a YAML file defining a CUSTOM-001 rule into tmp_path."""
    yaml_content = dedent("""\
        rules:
          - id: "CUSTOM-BILLING-001"
            name: "No DELETE on billing schema"
            description: "DELETE operations on billing schema are forbidden."
            dimension: "security"
            severity: "critical"
            pattern: "(?i)DELETE\\\\s+FROM\\\\s+billing\\\\."
            message: "DELETE on billing schema is forbidden."
    """)
    f = tmp_path / "billing_rules.yml"
    f.write_text(yaml_content)
    return tmp_path


def make_python_plugin(tmp_path: Path) -> Path:
    """Write a Python file defining a CUSTOM-AUDIT-001 rule into tmp_path."""
    code = dedent("""\
        from slowql.rules.base import PatternRule
        from slowql.core.models import Severity, Dimension

        class AuditColumnRule(PatternRule):
            id = "CUSTOM-AUDIT-001"
            name = "Missing audit columns"
            description = "Tables should have created_at."
            severity = Severity.MEDIUM
            dimension = Dimension.QUALITY
            pattern = r"(?i)CREATE\\s+TABLE\\s+\\w+"
            message_template = "Table may be missing audit columns: {match}"
    """)
    f = tmp_path / "audit_rules.py"
    f.write_text(code)
    return tmp_path


class TestEngineWithYAMLPlugin:
    def test_yaml_custom_rule_fires_on_violation(self, tmp_path: Path) -> None:
        plugin_dir = make_yaml_plugin(tmp_path)
        config = Config(
            analysis=AnalysisConfig(),
            plugins=PluginConfig(directories=[str(plugin_dir)]),
        )
        engine = SlowQL(config=config)
        result = engine.analyze(BILLING_SQL)
        assert any(i.rule_id == "CUSTOM-BILLING-001" for i in result.issues)

    def test_yaml_custom_rule_does_not_fire_on_safe_sql(self, tmp_path: Path) -> None:
        plugin_dir = make_yaml_plugin(tmp_path)
        config = Config(
            analysis=AnalysisConfig(),
            plugins=PluginConfig(directories=[str(plugin_dir)]),
        )
        engine = SlowQL(config=config)
        result = engine.analyze(SAFE_SQL)
        assert not any(i.rule_id == "CUSTOM-BILLING-001" for i in result.issues)


class TestEngineWithPythonPlugin:
    def test_python_custom_rule_fires_on_violation(self, tmp_path: Path) -> None:
        plugin_dir = make_python_plugin(tmp_path)
        config = Config(
            analysis=AnalysisConfig(),
            plugins=PluginConfig(directories=[str(plugin_dir)]),
        )
        engine = SlowQL(config=config)
        result = engine.analyze("CREATE TABLE users (id INT);")
        assert any(i.rule_id == "CUSTOM-AUDIT-001" for i in result.issues)

    def test_python_custom_rule_does_not_fire_on_safe_sql(self, tmp_path: Path) -> None:
        plugin_dir = make_python_plugin(tmp_path)
        config = Config(
            analysis=AnalysisConfig(),
            plugins=PluginConfig(directories=[str(plugin_dir)]),
        )
        engine = SlowQL(config=config)
        result = engine.analyze(SAFE_SQL)
        assert not any(i.rule_id == "CUSTOM-AUDIT-001" for i in result.issues)


class TestEngineWithNoPlugin:
    def test_no_plugins_no_custom_issues(self) -> None:
        engine = SlowQL()
        result = engine.analyze(BILLING_SQL)
        custom_ids = [i.rule_id for i in result.issues if i.rule_id.startswith("CUSTOM-")]
        assert custom_ids == []


class TestEngineWithBothPluginTypes:
    def test_both_yaml_and_python_rules_fire(self, tmp_path: Path) -> None:
        make_yaml_plugin(tmp_path)
        make_python_plugin(tmp_path)
        config = Config(
            analysis=AnalysisConfig(),
            plugins=PluginConfig(directories=[str(tmp_path)]),
        )
        engine = SlowQL(config=config)
        combined_sql = "DELETE FROM billing.orders WHERE id=1;\nCREATE TABLE log (id INT);"
        result = engine.analyze(combined_sql)
        ids = {i.rule_id for i in result.issues}
        assert "CUSTOM-BILLING-001" in ids
        assert "CUSTOM-AUDIT-001" in ids


class TestConfigFromYAMLFile:
    def test_config_file_with_plugin_directory(self, tmp_path: Path) -> None:
        """Engine loads plugin config from a YAML config file."""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        make_yaml_plugin(plugin_dir)

        config_content = dedent(f"""\
            plugins:
              directories:
                - "{plugin_dir}"
        """)
        config_file = tmp_path / "slowql.yaml"
        config_file.write_text(config_content)

        config = Config.from_file(config_file)
        engine = SlowQL(config=config)
        result = engine.analyze(BILLING_SQL)
        assert any(i.rule_id == "CUSTOM-BILLING-001" for i in result.issues)
