# slowql/src/slowql/plugins/yaml_loader.py
"""YAML-based rule loader for SlowQL.

This module provides functionality to load custom rules from YAML files.
Each rule is translated into a `PatternRule` instance.

YAML Schema:
    rules:
      - id: "CUSTOM-001"
        name: "Description of the rule"
        description: "Detailed explanation."
        dimension: "security"   # one of: security, performance, reliability, compliance, cost, quality
        severity: "critical"    # one of: critical, high, medium, low, info
        pattern: "regex pattern"
        message: "Human-readable message for the finding."
        tags: ["tag1", "tag2"]  # optional

Example:
    >>> from slowql.plugins.yaml_loader import YAMLRuleLoader
    >>> rules = YAMLRuleLoader.load_from_file("my_rules.yml")
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from slowql.core.models import Dimension, Severity
from slowql.rules.base import PatternRule

if TYPE_CHECKING:
    from slowql.rules.base import Rule

logger = logging.getLogger(__name__)

_yaml: Any

try:
    import yaml
    _yaml = yaml
except ImportError:  # pragma: no cover
    _yaml = None

# Mapping from YAML strings to model enums
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_DIMENSION_MAP: dict[str, Dimension] = {
    "security": Dimension.SECURITY,
    "performance": Dimension.PERFORMANCE,
    "reliability": Dimension.RELIABILITY,
    "compliance": Dimension.COMPLIANCE,
    "cost": Dimension.COST,
    "quality": Dimension.QUALITY,
}


def _build_pattern_rule(spec: dict[str, Any]) -> PatternRule:
    """Create a concrete PatternRule from a YAML rule spec dictionary.

    Args:
        spec: Parsed YAML dict for a single rule.

    Returns:
        A PatternRule subclass instance.

    Raises:
        ValueError: If a required field is missing or invalid.
    """
    # Validate required fields
    if not spec.get("id"):
        raise ValueError("YAML rule is missing required field 'id'.")
    if not spec.get("pattern"):
        raise ValueError(f"YAML rule '{spec.get('id', 'unknown')}' is missing required field 'pattern'.")

    rule_id: str = str(spec["id"])
    name: str = str(spec.get("name", rule_id))
    description: str = str(spec.get("description", ""))
    message: str = str(spec.get("message", "Pattern matched."))
    tags: tuple[str, ...] = tuple(str(t) for t in spec.get("tags", []))

    # Severity
    severity_raw = str(spec.get("severity", "medium")).lower()
    if severity_raw not in _SEVERITY_MAP:
        raise ValueError(
            f"Invalid severity '{severity_raw}' in rule '{rule_id}'. "
            f"Must be one of: {', '.join(_SEVERITY_MAP)}."
        )
    severity = _SEVERITY_MAP[severity_raw]

    # Dimension
    dimension_raw = str(spec.get("dimension", "quality")).lower()
    if dimension_raw not in _DIMENSION_MAP:
        raise ValueError(
            f"Invalid dimension '{dimension_raw}' in rule '{rule_id}'. "
            f"Must be one of: {', '.join(_DIMENSION_MAP)}."
        )
    dimension = _DIMENSION_MAP[dimension_raw]

    pattern: str = str(spec["pattern"])

    # Build a concrete PatternRule class dynamically
    rule_cls: type[PatternRule] = type(
        f"YamlRule_{rule_id.replace('-', '_')}",
        (PatternRule,),
        {
            "id": rule_id,
            "name": name,
            "description": description,
            "severity": severity,
            "dimension": dimension,
            "pattern": pattern,
            "message_template": message,
            "pattern_flags": re.IGNORECASE,
            "tags": tags,
        },
    )
    return rule_cls()


class YAMLRuleLoader:
    """Loads custom rules from YAML files or YAML strings.

    This class is stateless; all methods are class methods.

    Example:
        >>> rules = YAMLRuleLoader.load_from_file("my_rules.yml")
        >>> rules = YAMLRuleLoader.load_from_string(yaml_text)
    """

    @classmethod
    def load_from_string(cls, content: str) -> list[Rule]:
        """Parse a YAML string and return a list of Rule instances.

        Args:
            content: YAML string defining custom rules.

        Returns:
            List of Rule instances.

        Raises:
            ValueError: If a rule definition is invalid.
        """
        if _yaml is None:  # pragma: no cover
            raise RuntimeError("PyYAML is required for YAML rule files: pip install pyyaml")

        data: Any = _yaml.safe_load(content)
        if not isinstance(data, dict):
            return []

        rule_specs: list[Any] = data.get("rules", [])
        if not isinstance(rule_specs, list):
            return []

        rules: list[Rule] = []
        for spec in rule_specs:
            if not isinstance(spec, dict):
                continue
            rule = _build_pattern_rule(spec)
            rules.append(rule)

        return rules

    @classmethod
    def load_from_file(cls, path: Path | str) -> list[Rule]:
        """Load rules from a YAML file.

        Args:
            path: Path to a `.yml` or `.yaml` file.

        Returns:
            List of Rule instances.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If a rule definition is invalid.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"YAML rule file not found: {p}")

        content = p.read_text(encoding="utf-8")
        return cls.load_from_string(content)
