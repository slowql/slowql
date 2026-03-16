"""
Performance rules.
"""

from __future__ import annotations

from .aggregation import *
from .batching import *
from .clickhouse import *
from .cursors import *
from .duckdb import *
from .execution import *
from .hints import *
from .indexing import *
from .joins import *
from .locking import *
from .memory import *
from .network import *
from .presto import *
from .redshift import *
from .scanning import *
from .spark import *
from .sqlite import *

__all__ = [
    "BigQueryDistinctOnUnnestRule",
    "BigQueryRegexOnLargeTableRule",
    "CartesianProductRule",
    "ClickHouseJoinWithoutGlobalRule",
    "ClickHouseSelectWithoutPrewhereRule",
    "CoalesceOnIndexedColumnRule",
    "CompositeIndexOrderViolationRule",
    "CorrelatedSubqueryRule",
    "CountStarWithoutWhereRule",
    "CursorDeclarationRule",
    "DeepOffsetPaginationRule",
    "DistinctOnLargeSetRule",
    "DuckDBCopyWithoutFormatRule",
    "DuckDBLargeInListRule",
    "ExcessiveColumnCountRule",
    "ForceIndexHintMysqlRule",
    "FunctionOnIndexedColumnRule",
    "GroupByHighCardinalityRule",
    "HavingWithoutGroupByRule",
    "IlikeOnIndexedColumnRule",
    "ImplicitConversionInJoinRule",
    "ImplicitTypeConversionRule",
    "IndexHintRule",
    "LargeInClauseRule",
    "LargeObjectUnboundedRule",
    "LargeUnbatchedOperationRule",
    "LeadingWildcardRule",
    "LeftJoinWithIsNotNullRule",
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
    "PrestoCrossJoinRule",
    "PrestoOrderByWithoutLimitRule",
    "QueryOptimizerHintRule",
    "ReadUncommittedHintRule",
    "RedshiftSelectStarRule",
    "ScalarUdfInQueryRule",
    "SelectForUpdateWithoutLimitMysqlRule",
    "SelectForUpdateWithoutNowaitPgRule",
    "SelectIntoTempWithoutIndexRule",
    "SelectStarRule",
    "SparkBroadcastHintRule",
    "SparkUdfInWhereRule",
    "SqliteAutoIncrementRule",
    "SqliteWalModeRule",
    "TableLockHintRule",
    "TooManyJoinsRule",
    "UnboundedSelectRule",
    "UnboundedTempTableRule",
    "UnfilteredAggregationRule",
    "WhileLoopPatternRule",
]
