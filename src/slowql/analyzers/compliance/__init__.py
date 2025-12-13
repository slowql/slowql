# slowql/src/slowql/analyzers/compliance/__init__.py
"""
Compliance Analyzer for SlowQL.

This analyzer checks for potential violations of data protection regulations
like GDPR, HIPAA, and PCI-DSS by identifying sensitive data access patterns.
"""

from __future__ import annotations

from slowql.analyzers.base import RuleBasedAnalyzer
from slowql.core.models import Dimension
from slowql.rules.base import Rule


class ComplianceAnalyzer(RuleBasedAnalyzer):
    """
    Analyzer for regulatory compliance.
    
    Checks for:
    - PII (Personally Identifiable Information) access
    - Financial data handling
    - Data cross-border transfer indicators
    """

    name = "compliance"
    dimension = Dimension.COMPLIANCE
    description = "Checks for GDPR/HIPAA/PCI-DSS compliance risks."
    priority = 30

    def get_rules(self) -> list[Rule]:
        """
        Get compliance rules from the catalog.
        """
        from slowql.rules.catalog import PIIExposureRule

        return [
            PIIExposureRule(),
        ]