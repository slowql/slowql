from __future__ import annotations

"""
Cost rules module.
"""

from .compute import *
from .cross_region import *
from .indexing import *
from .io import *
from .lifecycle import *
from .network import *
from .pagination import *
from .serverless import *
from .storage import *

__all__ = [
    'FullTableScanRule',
    'ExpensiveWindowFunctionRule',
    'CrossDatabaseJoinRule',
    'MultiRegionQueryLatencyRule',
    'DistributedTransactionOverheadRule',
    'DuplicateIndexSignalRule',
    'OverIndexedTableSignalRule',
    'MissingCoveringIndexOpportunityRule',
    'RedundantIndexColumnOrderRule',
    'RedundantOrderByRule',
    'OldDataNotArchivedRule',
    'LargeTextColumnWithoutCompressionRule',
    'LargeTableWithoutPartitioningRule',
    'CrossRegionDataTransferCostRule',
    'OffsetPaginationWithoutCoveringIndexRule',
    'DeepPaginationWithoutCursorRule',
    'CountStarForPaginationRule',
    'ColdStartQueryPatternRule',
    'UnnecessaryConnectionPoolingRule',
    'SelectStarInETLRule',
]
