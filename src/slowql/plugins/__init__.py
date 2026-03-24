# slowql/src/slowql/plugins/__init__.py
"""SlowQL Plugin API for third-party rule developers.

This package exposes the public API for loading custom rules via Python
modules and YAML configuration files.

Example:
    >>> from slowql.plugins import PluginManager
    >>> mgr = PluginManager(directories=["./my_rules"])
    >>> rules = mgr.load_rules()
"""

from slowql.plugins.manager import PluginManager
from slowql.plugins.yaml_loader import YAMLRuleLoader

__all__ = ["PluginManager", "YAMLRuleLoader"]
