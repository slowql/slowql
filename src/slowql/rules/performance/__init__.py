"""
Performance rules.
"""

from __future__ import annotations

from .aggregation import *
from .batching import *
from .cursors import *
from .execution import *
from .hints import *
from .indexing import *
from .joins import *
from .locking import *
from .memory import *
from .network import *
from .redshift import *
from .scanning import *
from .sqlite import *

__all__ = [
    "BigQueryDistinctOnUnnestRule",
    "BigQueryRegexOnLargeTableRule",
    "CartesianProductRule",
    "CoalesceOnIndexedColumnRule",
    "CompositeIndexOrderViolationRule",
    "CorrelatedSubqueryRule",
    "CountStarWithoutWhereRule",
    "CursorDeclarationRule",
    "DeepOffsetPaginationRule",
    "DistinctOnLargeSetRule",
    "ExcessiveColumnCountRule",
    "ForceIndexHintMysqlRule",
    "FunctionOnIndexedColumnRule",
    "GroupByHighCardinalityRule",
    "IlikeOnIndexedColumnRule",
    "ImplicitConversionInJoinRule",
    "ImplicitTypeConversionRule",
    "IndexHintRule",
    "LargeInClauseRule",
    "LargeObjectUnboundedRule",
    "LargeUnbatchedOperationRule",
    "LeadingWildcardRule",
    "LikeWithoutCollateNocaseRule",
    "LongTransactionPatternRule",
    "MissingBatchSizeInLoopRule",
    "MissingSetNocountRule",
    "MissingTransactionIsolationRule",
    "MissingWhereRule",
    "NegationOnIndexedColumnRule",
    "NestedLoopJoinHintRule",
    "NonSargableOrConditionRule",
    "NotInNullableSubqueryRule",
    "NotInOnRedshiftRule",
    "NotInSubqueryRule",
    "OrOnIndexedColumnsRule",
    "OracleForUpdateWithoutNowaitRule",
    "OrderByInSubqueryRule",
    "OrderByNonIndexedColumnRule",
    "OrderByRandRule",
    "OrderByWithoutLimitInSubqueryRule",
    "OrderByWithoutLimitRedshiftRule",
    "ParallelQueryHintRule",
    "QueryOptimizerHintRule",
    "ReadUncommittedHintRule",
    "RedshiftSelectStarRule",
    "ScalarUdfInQueryRule",
    "SelectForUpdateWithoutLimitMysqlRule",
    "SelectForUpdateWithoutNowaitPgRule",
    "SelectIntoTempWithoutIndexRule",
    "SelectStarRule",
    "SqliteAutoIncrementRule",
    "SqliteWalModeRule",
    "TableLockHintRule",
    "TooManyJoinsRule",
    "UnboundedSelectRule",
    "UnboundedTempTableRule",
    "UnfilteredAggregationRule",
    "WhileLoopPatternRule",
]
