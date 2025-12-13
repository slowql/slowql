# slowql/src/slowql/analyzers/security/__init__.py
"""
Security Analyzer for SlowQL.

This analyzer focuses on detecting security vulnerabilities in SQL queries,
including:
- SQL Injection risks
- Authentication bypass risks
- Excessive privileges
- Sensitive data exposure
"""

from __future__ import annotations

from typing import Any

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension, Severity
from slowql.rules.base import Rule


class SecurityAnalyzer(RuleBasedAnalyzer):
    """
    Analyzer for security vulnerabilities.
    
    Checks for patterns and AST structures that indicate security risks
    mapped to OWASP Top 10 and other security standards.
    """

    name = "security"
    dimension = Dimension.SECURITY
    description = "Detects SQL injection, hardcoded secrets, and privilege issues."
    priority = 10  # High priority, security first

    def get_rules(self) -> list[Rule]:
        """
        Get security rules from the catalog.
        
        Returns:
            List of security rules.
        """
        from slowql.rules.catalog import (
            GrantAllRule,
            HardcodedPasswordRule,
            SQLInjectionRule,
        )

        return [
            SQLInjectionRule(),
            HardcodedPasswordRule(),
            GrantAllRule(),
        ]
    
    def analyze(self, query: Any, *, config: Any = None) -> list[Any]:
        """
        Run security analysis.
        
        Extends base analysis with specific security metadata.
        """
        issues = super().analyze(query, config=config)
        
        # Add security metadata to issues
        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                issue.metadata["security_alert"] = True
                
        return issues