from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from slowql.core.models import (
    Dimension,
    Fix,
    FixConfidence,
    RemediationMode,
    Severity,
)
from slowql.rules.base import PatternRule

if TYPE_CHECKING:
    from slowql.core.models import Issue, Query


class JSONBOperatorSpacingRule(PatternRule):
    """Detects inconsistent spacing around PostgreSQL JSONB operators."""

    id: ClassVar[str] = "QUAL-PG-002"
    name: ClassVar[str] = "JSONB Operator Spacing"
    description: ClassVar[str] = "JSONB operators (->, ->>, #>, #>>) should have consistent spacing"
    severity: ClassVar[Severity] = Severity.LOW
    dimension: ClassVar[Dimension] = Dimension.QUALITY
    dialects: ClassVar[tuple[str, ...]] = ("postgresql",)
    remediation_mode: ClassVar[RemediationMode] = RemediationMode.SAFE_APPLY

    pattern: ClassVar[str] = r"\b(\w+)\s{2,}(->>?|#>>?)\s+"
    message_template: ClassVar[str] = "Inconsistent spacing around JSONB operator '{match}'"

    def check(self, query: Query) -> list[Issue]:
        """Check for spacing issues around JSONB operators."""
        if not self._dialect_matches(query):
            return []

        issues = []
        for match in re.finditer(self.pattern, query.raw, re.IGNORECASE):
            column = match.group(1)
            operator = match.group(2)
            original = match.group(0)
            replacement = f"{column} {operator} "

            issues.append(
                self.create_issue(
                    query=query,
                    message=f"Inconsistent spacing around JSONB operator '{operator}'. Use single spaces for readability.",
                    snippet=original.strip(),
                    fix=Fix(
                        rule_id=self.id,
                        description=f"Normalize spacing around '{operator}' operator",
                        original=original,
                        replacement=replacement,
                        confidence=FixConfidence.SAFE,
                    ),
                )
            )

        return issues
