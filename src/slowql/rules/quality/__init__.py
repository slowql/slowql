"""
Quality rules module.
"""

from __future__ import annotations

from .complexity import *
from .dbt import *
from .documentation import *
from .dry_principles import *
from .duckdb import *
from .modern_sql import *
from .naming import *
from .null_handling import *
from .schema_design import *
from .style import *
from .technical_debt import *
from .testing import *

__all__ = [
    "AmbiguousAliasRule",
    "AnsiNullsOffRule",
    "CaseWithoutElseRule",
    "CommentedCodeRule",
    "ComplexLogicWithoutExplanationRule",
    "CyclomaticComplexityRule",
    "DbtHardcodedSchemaRule",
    "DbtMissingRefRule",
    "DuckDBOldStyleCastRule",
    "DuplicateConditionRule",
    "ExcessiveCaseNestingRule",
    "ExcessiveSubqueryNestingRule",
    "GodQueryRule",
    "HardcodedDateRule",
    "HardcodedTestDataRule",
    "HungarianNotationRule",
    "ImplicitJoinRule",
    "InconsistentTableNamingRule",
    "InsertWithoutColumnListRule",
    "LackOfIndexingOnForeignKeyRule",
    "LongQueryRule",
    "MagicStringWithoutCommentRule",
    "MissingAliasRule",
    "MissingColumnCommentsRule",
    "MissingForeignKeyRule",
    "MissingPrimaryKeyRule",
    "MysqlGroupByImplicitSortRule",
    "MysqlLockInShareModeRule",
    "NonDeterministicQueryRule",
    "NullComparisonRule",
    "OracleNvlInWhereRule",
    "OrderByMissingForPaginationRule",
    "ReservedWordAsColumnRule",
    "RownumWithoutOrderByRule",
    "SelectFromDualRule",
    "SelectWithoutFromRule",
    "SqlCalcFoundRowsRule",
    "StraightJoinHintRule",
    "TempTableNotCleanedUpRule",
    "TodoFixmeCommentRule",
    "TsqlQuotedIdentifierOffRule",
    "UnionWithoutAllRule",
    "UsingFloatForCurrencyRule",
    "WildcardInColumnListRule",
]
