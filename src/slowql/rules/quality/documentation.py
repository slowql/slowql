"""
Quality Documentation rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    'ComplexLogicWithoutExplanationRule',
    'MagicStringWithoutCommentRule',
    'MissingColumnCommentsRule',
]


class MissingColumnCommentsRule(PatternRule):
    """Detects CREATE TABLE statements without column comments."""

    id = "QUAL-DOC-001"
    name = "Missing Column Comments"
    description = "Detects table definitions missing COMMENT or DESCRIPTION metadata."
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_DOCUMENTATION

    pattern = r'CREATE\s+TABLE\s+(?:(?!COMMENT).)*?(?:\);|\Z)'

    impact = (
        "Missing comments mean the business meaning of columns must be reverse-engineered "
        "from code. This slows down onboarding and leads to data misuse."
    )
    fix_guidance = (
        "Add COMMENT 'description' to all column definitions. Explain units (e.g., 'price in USD') "
        "and expected values."
    )


class MagicStringWithoutCommentRule(PatternRule):
    """Detects magic strings/numbers without explanatory comments."""

    id = "QUAL-DOC-002"
    name = "Magic Constant Without Comment"
    description = "Detects hardcoded literals used in filters without inline comments."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_DOCUMENTATION

    pattern = r'(?<!--)WHERE\s+.*\s*=\s*[\'"].+[\'"](?!\s*--)'

    impact = (
        "Magic constants like 'STATUS_42' or 1001 represent business logic that is "
        "opaque to future maintainers. Without comments, it's impossible to know if the value is correct."
    )
    fix_guidance = (
        "Add an inline comment explaining what the constant represents. E.g., "
        "WHERE status = 'A' -- A = Active."
    )


class ComplexLogicWithoutExplanationRule(Rule):
    """Detects long blocks of code without comments."""

    id = "QUAL-DOC-003"
    name = "Complex Logic Without Explanation"
    description = "Detects long queries (>20 lines) that have no comments."
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_DOCUMENTATION

    def check(self, query: Query) -> list[Issue]:
        issues = []
        # Count complex components in raw query
        score = query.raw.count('AND') + query.raw.count('OR') + query.raw.count('CASE')
        has_comment = "--" in query.raw or "/*" in query.raw

        if score >= 5 and not has_comment:
            issues.append(
                self.create_issue(
                    query=query,
                    message=f"Complex logic (score: {score}) without explanation.",
                    snippet=query.raw[:50]
                )
            )
        return issues

    impact = (
        "Queries over 20 lines without comments are 'write-only' code. They are "
        "prohibitively expensive to modify or peer-review safely."
    )
    fix_guidance = (
        "Add header comments explaining the query's goal. Use inline comments for "
        "complex JOIN conditions or business logic branches."
    )
