# slowql/tests/unit/test_plugins_manager.py
"""Unit tests for the plugin manager (Python module loading)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

from slowql.plugins.manager import PluginManager


class TestPluginManagerInit:
    def test_instantiates_with_empty_lists(self) -> None:
        mgr = PluginManager()
        assert mgr.directories == []
        assert mgr.modules == []

    def test_accepts_directories_and_modules(self, tmp_path: Path) -> None:
        mgr = PluginManager(directories=[str(tmp_path)], modules=["os"])
        assert str(tmp_path) in mgr.directories
        assert "os" in mgr.modules


class TestPluginManagerLoad:
    def test_load_from_python_file(self, tmp_path: Path) -> None:
        """A .py file with a Rule subclass is discovered and returned."""
        plugin_code = '''
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

class BillingDeleteRule(PatternRule):
    id = "CUSTOM-BILLING-001"
    name = "No DELETE on billing"
    description = "DELETE on billing schema is forbidden."
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    pattern = r"(?i)DELETE\\s+FROM\\s+billing\\."
    message_template = "DELETE on billing schema: {match}"
'''
        plugin_file = tmp_path / "my_rules.py"
        plugin_file.write_text(plugin_code)

        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()

        assert len(rules) == 1
        assert rules[0].id == "CUSTOM-BILLING-001"

    def test_load_from_module_string(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A dotted module name can be specified and loaded."""
        plugin_code = '''
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

class AuditTableRule(PatternRule):
    id = "CUSTOM-AUDIT-001"
    name = "Audit required columns"
    description = "Audit tables must have created_at."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    pattern = r"(?i)CREATE\\s+TABLE"
    message_template = "Table missing audit columns."
'''
        # Write as a package inside tmp_path
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "audit_rules.py").write_text(plugin_code)

        monkeypatch.syspath_prepend(str(tmp_path))

        mgr = PluginManager(modules=["mypkg.audit_rules"])
        rules = mgr.load_rules()

        assert any(r.id == "CUSTOM-AUDIT-001" for r in rules)

    def test_empty_directories_returns_no_rules(self, tmp_path: Path) -> None:
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        assert rules == []

    def test_invalid_directory_skipped_gracefully(self) -> None:
        mgr = PluginManager(directories=["/nonexistent/path/xyz"])
        # Should not raise
        rules = mgr.load_rules()
        assert rules == []

    def test_invalid_module_skipped_gracefully(self) -> None:
        mgr = PluginManager(modules=["no_such_module_xyz_abc"])
        rules = mgr.load_rules()
        assert rules == []

    def test_file_with_syntax_error_skipped_gracefully(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("this is not valid python !!! @@##")
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        assert rules == []

    def test_non_rule_classes_are_ignored(self, tmp_path: Path) -> None:
        """Classes that do not extend Rule are not collected."""
        code = '''
class NotARule:
    id = "NOT-A-RULE"
'''
        (tmp_path / "not_rule.py").write_text(code)
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        assert rules == []

    def test_abstract_rule_base_is_not_included(self, tmp_path: Path) -> None:
        """Only concrete rules (with id defined) are collected."""
        code = '''
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

# Concrete subclass should be collected
class MyRule(PatternRule):
    id = "CUSTOM-TEST-001"
    name = "Test rule"
    description = "Test."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    pattern = r"SELECT 1"
    message_template = "Matched."
'''
        (tmp_path / "concrete.py").write_text(code)
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        assert any(r.id == "CUSTOM-TEST-001" for r in rules)

    def test_duplicate_rule_ids_are_deduplicated(self, tmp_path: Path) -> None:
        """The same rule ID from two files should only appear once."""
        code = '''
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

class DupeRule(PatternRule):
    id = "CUSTOM-DUPE-001"
    name = "Dupe"
    description = "."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    pattern = r"x"
    message_template = "x"
'''
        (tmp_path / "dupe1.py").write_text(code)
        (tmp_path / "dupe2.py").write_text(code)
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        ids = [r.id for r in rules]
        assert ids.count("CUSTOM-DUPE-001") == 1

    def test_load_yaml_rules_from_directory(self, tmp_path: Path) -> None:
        """YAML files in directories are also loaded."""
        yaml_content = """\
rules:
  - id: "CUSTOM-SCHEMA-001"
    name: "No DELETE on billing"
    description: "Prevent deletes on billing."
    dimension: "security"
    severity: "critical"
    pattern: "(?i)DELETE\\\\s+FROM\\\\s+billing\\\\."
    message: "DELETE on billing schema is forbidden."
"""
        (tmp_path / "my_rules.yml").write_text(yaml_content)
        mgr = PluginManager(directories=[str(tmp_path)])
        rules = mgr.load_rules()
        assert any(r.id == "CUSTOM-SCHEMA-001" for r in rules)
