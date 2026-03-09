from __future__ import annotations

"""
Quality rules module.
"""

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
    'ExcessiveCaseNestingRule',
    'ExcessiveSubqueryNestingRule',
    'GodQueryRule',
    'CyclomaticComplexityRule',
    'LongQueryRule',
    'MissingColumnCommentsRule',
    'MagicStringWithoutCommentRule',
    'ComplexLogicWithoutExplanationRule',
    'DuplicateConditionRule',
    'ImplicitJoinRule',
    'HardcodedDateRule',
    'UnionWithoutAllRule',
    'InconsistentTableNamingRule',
    'AmbiguousAliasRule',
    'HungarianNotationRule',
    'ReservedWordAsColumnRule',
    'NullComparisonRule',
    'MissingPrimaryKeyRule',
    'MissingForeignKeyRule',
    'LackOfIndexingOnForeignKeyRule',
    'UsingFloatForCurrencyRule',
    'SelectWithoutFromRule',
    'WildcardInColumnListRule',
    'MissingAliasRule',
    'CommentedCodeRule',
    'TodoFixmeCommentRule',
    'TempTableNotCleanedUpRule',
    'NonDeterministicQueryRule',
    'OrderByMissingForPaginationRule',
    'HardcodedTestDataRule',
]
