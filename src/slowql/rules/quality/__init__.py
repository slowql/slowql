"""
Quality rules module.
"""

from __future__ import annotations

from .complexity import *
from .documentation import *
from .dry_principles import *
from .modern_sql import *
from .naming import *
from .null_handling import *
from .schema_design import *
from .style import *
from .technical_debt import *
from .testing import *

__all__ = [
    "AmbiguousAliasRule",
    "CommentedCodeRule",
    "ComplexLogicWithoutExplanationRule",
    "CyclomaticComplexityRule",
    "DuplicateConditionRule",
    "ExcessiveCaseNestingRule",
    "ExcessiveSubqueryNestingRule",
    "GodQueryRule",
    "HardcodedDateRule",
    "HardcodedTestDataRule",
    "HungarianNotationRule",
    "ImplicitJoinRule",
    "InconsistentTableNamingRule",
    "LackOfIndexingOnForeignKeyRule",
    "LongQueryRule",
    "MagicStringWithoutCommentRule",
    "MissingAliasRule",
    "MissingColumnCommentsRule",
    "MissingForeignKeyRule",
    "MissingPrimaryKeyRule",
    "NonDeterministicQueryRule",
    "NullComparisonRule",
    "OrderByMissingForPaginationRule",
    "ReservedWordAsColumnRule",
    "RownumWithoutOrderByRule",
    "SelectFromDualRule",
    "SelectWithoutFromRule",
    "TempTableNotCleanedUpRule",
    "TodoFixmeCommentRule",
    "UnionWithoutAllRule",
    "UsingFloatForCurrencyRule",
    "WildcardInColumnListRule",
]
