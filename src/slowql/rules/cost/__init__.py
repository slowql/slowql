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
    'ColdStartQueryPatternRule',
    'CountStarForPaginationRule',
    'CrossDatabaseJoinRule',
    'CrossRegionDataTransferCostRule',
    'DeepPaginationWithoutCursorRule',
    'DistributedTransactionOverheadRule',
    'DuplicateIndexSignalRule',
    'ExpensiveWindowFunctionRule',
    'FullTableScanRule',
    'LargeTableWithoutPartitioningRule',
    'LargeTextColumnWithoutCompressionRule',
    'MissingCoveringIndexOpportunityRule',
    'MultiRegionQueryLatencyRule',
    'OffsetPaginationWithoutCoveringIndexRule',
    'OldDataNotArchivedRule',
    'OverIndexedTableSignalRule',
    'RedundantIndexColumnOrderRule',
    'RedundantOrderByRule',
    'SelectStarInETLRule',
    'UnnecessaryConnectionPoolingRule',
]
