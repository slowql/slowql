from __future__ import annotations

"""
Performance rules module.
"""

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
    'UnfilteredAggregationRule',
    'OrderByInSubqueryRule',
    'LargeUnbatchedOperationRule',
    'MissingBatchSizeInLoopRule',
    'CursorDeclarationRule',
    'WhileLoopPatternRule',
    'NestedLoopJoinHintRule',
    'ScalarUdfInQueryRule',
    'CorrelatedSubqueryRule',
    'OrderByNonIndexedColumnRule',
    'QueryOptimizerHintRule',
    'IndexHintRule',
    'ParallelQueryHintRule',
    'LeadingWildcardRule',
    'FunctionOnIndexedColumnRule',
    'OrOnIndexedColumnsRule',
    'DeepOffsetPaginationRule',
    'ImplicitTypeConversionRule',
    'CompositeIndexOrderViolationRule',
    'NonSargableOrConditionRule',
    'CoalesceOnIndexedColumnRule',
    'NegationOnIndexedColumnRule',
    'CartesianProductRule',
    'TooManyJoinsRule',
    'TableLockHintRule',
    'ReadUncommittedHintRule',
    'LongTransactionPatternRule',
    'MissingTransactionIsolationRule',
    'LargeInClauseRule',
    'UnboundedTempTableRule',
    'OrderByWithoutLimitInSubqueryRule',
    'GroupByHighCardinalityRule',
    'ExcessiveColumnCountRule',
    'LargeObjectUnboundedRule',
    'SelectStarRule',
    'MissingWhereRule',
    'DistinctOnLargeSetRule',
    'UnboundedSelectRule',
    'NotInSubqueryRule',
]
