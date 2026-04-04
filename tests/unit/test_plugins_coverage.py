"""Targeted coverage tests for plugins/manager.py uncovered lines."""
from __future__ import annotations

import tempfile
from pathlib import Path

from slowql.plugins.manager import PluginManager


def test_load_python_plugin_with_invalid_rule_class():
    """Covers: Failed to instantiate rule class warning branch."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_file = Path(tmpdir) / "bad_rule.py"
        plugin_file.write_text("""
from slowql.rules.base import Rule
from slowql.core.models import Query, Issue, Severity, Dimension, Category

class BrokenRule(Rule):
    id = "BROKEN-001"
    name = "Broken"
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    def __init__(self):
        raise RuntimeError("Cannot instantiate")

    def check(self, query: Query) -> list[Issue]:
        return []
""")
        manager = PluginManager(directories=[str(tmpdir)])
        rules = manager.load_rules()
        # Should not crash, just skip the broken rule
        assert isinstance(rules, list)


def test_load_python_plugin_with_duplicate_ids():
    """Covers: duplicate rule ID deduplication."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_file = Path(tmpdir) / "dup_rule.py"
        plugin_file.write_text("""
from slowql.rules.base import Rule
from slowql.core.models import Query, Issue, Severity, Dimension, Category

class DupRule1(Rule):
    id = "DUP-001"
    name = "Dup 1"
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    def check(self, query: Query) -> list[Issue]:
        return []

class DupRule2(Rule):
    id = "DUP-001"
    name = "Dup 2"
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    def check(self, query: Query) -> list[Issue]:
        return []
""")
        manager = PluginManager(directories=[str(tmpdir)])
        rules = manager.load_rules()
        dup_rules = [r for r in rules if r.id == "DUP-001"]
        assert len(dup_rules) == 1


def test_load_invalid_python_file():
    """Covers: spec is None or spec.loader is None branch."""
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "broken_syntax.py"
        bad_file.write_text("this is not valid python !!!! @@@ ###")
        manager = PluginManager(directories=[str(tmpdir)])
        rules = manager.load_rules()
        assert isinstance(rules, list)


def test_load_invalid_yaml_plugin():
    """Covers: failed YAML load warning branch."""
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_yaml = Path(tmpdir) / "bad_rules.yaml"
        bad_yaml.write_text("this: is: not: valid: yaml: !!!")
        manager = PluginManager(directories=[str(tmpdir)])
        rules = manager.load_rules()
        assert isinstance(rules, list)


def test_load_nonexistent_module_string():
    """Covers: Failed to import plugin module branch."""
    manager = PluginManager(modules=["nonexistent.module.that.does.not.exist"])
    rules = manager.load_rules()
    assert isinstance(rules, list)


def test_load_from_nonexistent_directory():
    """Covers: directory does not exist warning branch."""
    manager = PluginManager(directories=["/nonexistent/path/that/does/not/exist"])
    rules = manager.load_rules()
    assert isinstance(rules, list)
    assert len(rules) == 0


def test_empty_plugin_manager():
    """Covers: empty directories and modules."""
    manager = PluginManager()
    rules = manager.load_rules()
    assert isinstance(rules, list)
    assert len(rules) == 0
