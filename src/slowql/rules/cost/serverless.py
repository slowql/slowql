from __future__ import annotations

"""
Cost Serverless rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'ColdStartQueryPatternRule',
    'UnnecessaryConnectionPoolingRule',
]


class ColdStartQueryPatternRule(PatternRule):
    """Detects complex queries in serverless environments that trigger scaling."""

    id = "COST-SERVERLESS-001"
    name = "Cold Start Query Pattern"
    description = (
        "Detects complex queries in serverless environments (Aurora Serverless) "
        "that will trigger cold starts and ACU scaling, increasing costs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_SERVERLESS

    pattern = r"\bSELECT\b.*\b(JOIN|UNION|INTERSECT|EXCEPT)\b.*\b(GROUP\s+BY|ORDER\s+BY|DISTINCT)\b"
    message_template = "Complex query in serverless environment: potential cold start and scaling cost: {match}"

    impact = (
        "Complex queries trigger Aurora Capacity Unit (ACU) scaling. Each scale-up "
        "costs minimum $0.12/hour. Frequent scaling wastes budget."
    )
    fix_guidance = (
        "Keep queries simple in serverless. Pre-aggregate data or use materialized "
        "views. Set minimum ACUs appropriately."
    )


class UnnecessaryConnectionPoolingRule(PatternRule):
    """Detects wasteful connection management in serverless."""

    id = "COST-SERVERLESS-002"
    name = "Unnecessary Connection Pooling"
    description = (
        "Detects connection management patterns that are wasteful in serverless "
        "(connections held open unnecessarily)."
    )
    severity = Severity.INFO
    dimension = Dimension.COST
    category = Category.COST_SERVERLESS

    pattern = r"\b(SET\s+SESSION|CONNECTION\s+TIMEOUT\s*=\s*\d{4,}|KEEP\s+ALIVE|POOLING\s*=\s*TRUE)\b"
    message_template = " wasteful connection management found: {match}"

    impact = (
        "Serverless databases charge per second of connection time. Keeping connections "
        "alive between invocations wastes money."
    )
    fix_guidance = (
        "Close connections immediately after query in Lambda/serverless. Use RDS Proxy "
        "for connection pooling."
    )
