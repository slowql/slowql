from __future__ import annotations

"""
Cost Network rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'CrossRegionDataTransferCostRule',
]


class CrossRegionDataTransferCostRule(PatternRule):
    """Flags queries using database links, federated queries, or external tables."""

    id = "COST-NETWORK-001"
    name = "Cross-Region Data Transfer"
    description = (
        "Flags queries using database links, federated queries, or external table "
        "references that may cause cross-region data transfer. Cloud providers "
        "charge heavily for egress traffic."
    )
    severity = Severity.INFO
    dimension = Dimension.COST
    category = Category.COST_NETWORK

    pattern = r"\b(OPENQUERY|OPENDATASOURCE|EXTERNAL\s+TABLE|DBLink|@[\w\.]+)\b"
    message_template = "Potential cross-region data transfer detected: {match}"

    impact = (
        "Cross-region queries incur data egress charges (e.g., $0.09/GB in AWS). A "
        "single unoptimized federated query can transfer terabytes and generate "
        "unexpected bills."
    )
    fix_guidance = (
        "Minimize cross-region queries. Use data replication (read replicas, CDC) or "
        "cache results locally. For analytics, stage data in the same region as compute "
        "resources."
    )
