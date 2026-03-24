# slowql/src/slowql/plugins/manager.py
"""Plugin manager for SlowQL.

Discovers and loads custom rules from:
  - Directories: scans for `.py` and `.yml` / `.yaml` files.
  - Module strings: imports a dotted Python module name and inspects it.

All discovered `Rule` subclasses (with non-empty `id` class attribute) are
collected and returned. Duplicate rule IDs across multiple sources are
deduplicated — the first registration wins.

Example:
    >>> from slowql.plugins.manager import PluginManager
    >>> mgr = PluginManager(directories=["./my_rules"])
    >>> rules = mgr.load_rules()
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import sys
from pathlib import Path

from slowql.rules.base import Rule

logger = logging.getLogger(__name__)


def _is_concrete_rule(obj: object) -> bool:
    """Return True if *obj* is a concrete (non-abstract) Rule subclass with an id."""
    return (
        inspect.isclass(obj)
        and issubclass(obj, Rule)
        and obj is not Rule
        and bool(getattr(obj, "id", ""))
        # Exclude any Rule subclasses imported *from* slowql itself
        # (e.g. PatternRule, ASTRule) that the plugin file re-imports
        and obj.__module__ != "slowql.rules.base"
    )


def _collect_rules_from_module(mod: object) -> list[Rule]:
    """Inspect a loaded module and collect all concrete Rule subclasses."""
    seen_ids: set[str] = set()
    rules: list[Rule] = []

    for _name, obj in inspect.getmembers(mod, _is_concrete_rule):
        rule_id: str = obj.id
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        try:
            rules.append(obj())
        except Exception as exc:
            logger.warning("Failed to instantiate rule class %r: %s", obj, exc)

    return rules


def _load_python_file(path: Path) -> list[Rule]:
    """Dynamically load a .py file and collect Rule subclasses."""
    module_name = f"_slowql_plugin_{path.stem}_{abs(hash(str(path.resolve())))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        logger.warning("Cannot create module spec for %s — skipped.", path)
        return []

    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    try:
        assert spec.loader is not None
        spec.loader.exec_module(mod)
    except Exception as exc:
        logger.warning("Failed to load plugin file %s: %s", path, exc)
        sys.modules.pop(module_name, None)
        return []

    return _collect_rules_from_module(mod)


def _load_yaml_file(path: Path) -> list[Rule]:
    """Load YAML rule definitions from a file."""
    from slowql.plugins.yaml_loader import YAMLRuleLoader  # noqa: PLC0415

    try:
        return YAMLRuleLoader.load_from_file(path)
    except Exception as exc:
        logger.warning("Failed to load YAML plugin file %s: %s", path, exc)
        return []


def _load_module_string(module_name: str) -> list[Rule]:
    """Import a dotted module name and collect Rule subclasses."""
    try:
        mod = importlib.import_module(module_name)
    except Exception as exc:
        logger.warning("Failed to import plugin module %r: %s", module_name, exc)
        return []

    return _collect_rules_from_module(mod)


class PluginManager:
    """Discovers and loads custom rules from directories and module strings.

    Args:
        directories: Paths to directories to scan for `.py`, `.yml`, and
            `.yaml` plugin files.
        modules: Dotted Python module names to import and inspect for rules.

    Example:
        >>> mgr = PluginManager(directories=["./custom_rules"])
        >>> rules = mgr.load_rules()
        >>> print([r.id for r in rules])
    """

    def __init__(
        self,
        directories: list[str] | None = None,
        modules: list[str] | None = None,
    ) -> None:
        self.directories: list[str] = list(directories or [])
        self.modules: list[str] = list(modules or [])

    def load_rules(self) -> list[Rule]:
        """Discover and return all custom rules.

        Scans each configured directory for plugin files and imports each
        configured module. Rules with duplicate IDs are deduplicated — the
        first occurrence wins.

        Returns:
            List of Rule instances collected from all sources.
        """
        seen_ids: set[str] = set()
        all_rules: list[Rule] = []

        for directory in self.directories:
            dir_path = Path(directory)
            if not dir_path.exists() or not dir_path.is_dir():
                logger.warning("Plugin directory %r does not exist — skipped.", directory)
                continue

            for file_path in sorted(dir_path.iterdir()):
                if file_path.suffix == ".py":
                    rules = _load_python_file(file_path)
                elif file_path.suffix in {".yml", ".yaml"}:
                    rules = _load_yaml_file(file_path)
                else:
                    continue

                for rule in rules:
                    if rule.id not in seen_ids:
                        seen_ids.add(rule.id)
                        all_rules.append(rule)

        for module_name in self.modules:
            for rule in _load_module_string(module_name):
                if rule.id not in seen_ids:
                    seen_ids.add(rule.id)
                    all_rules.append(rule)

        return all_rules
