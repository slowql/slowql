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
from .scanning import *

__all__ = [
    "CartesianProductRule",
    "CoalesceOnIndexedColumnRule",
    "CompositeIndexOrderViolationRule",
    "CorrelatedSubqueryRule",
    "CursorDeclarationRule",
    "DeepOffsetPaginationRule",
    "DistinctOnLargeSetRule",
    "ExcessiveColumnCountRule",
    "FunctionOnIndexedColumnRule",
    "GroupByHighCardinalityRule",
    "IlikeOnIndexedColumnRule",
    "ImplicitTypeConversionRule",
    "IndexHintRule",
    "LargeInClauseRule",
    "LargeObjectUnboundedRule",
    "LargeUnbatchedOperationRule",
    "LeadingWildcardRule",
    "LongTransactionPatternRule",
    "MissingBatchSizeInLoopRule",
    "MissingTransactionIsolationRule",
    "MissingWhereRule",
    "NegationOnIndexedColumnRule",
    "NestedLoopJoinHintRule",
    "NonSargableOrConditionRule",
    "NotInSubqueryRule",
    "OrOnIndexedColumnsRule",
    "OrderByInSubqueryRule",
    "OrderByNonIndexedColumnRule",
    "OrderByWithoutLimitInSubqueryRule",
    "ParallelQueryHintRule",
    "QueryOptimizerHintRule",
    "ReadUncommittedHintRule",
    "ScalarUdfInQueryRule",
    "SelectStarRule",
    "TableLockHintRule",
    "TooManyJoinsRule",
    "UnboundedSelectRule",
    "UnboundedTempTableRule",
    "UnfilteredAggregationRule",
    "WhileLoopPatternRule",
]
