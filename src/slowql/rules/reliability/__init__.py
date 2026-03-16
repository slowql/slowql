"""
Reliability rules module.
"""

from __future__ import annotations

from .clickhouse import *
from .data_safety import *
from .deadlocks import *
from .error_handling import *
from .foreign_keys import *
from .idempotency import *
from .presto import *
from .race_conditions import *
from .redshift import *
from .spark import *
from .sqlite import *
from .timeouts import *
from .transactions import *

__all__ = [
    "AlterTableAddColumnVolatileDefaultRule",
    "AlterTableDestructiveRule",
    "AtAtIdentityRule",
    "AutocommitDisabledRule",
    "BigQueryDmlWithoutWhereOnPartitionedRule",
    "CascadeDeleteRiskRule",
    "ClickHouseSelectWithoutFinalRule",
    "ConnectByWithoutNocycleRule",
    "CopyWithoutManifestRule",
    "CreateIndexWithoutConcurrentlyRule",
    "DeadlockPatternRule",
    "DropTableRule",
    "EmptyTransactionRule",
    "ExceptionSwallowedRule",
    "InsertIgnoreRule",
    "LockEscalationRiskRule",
    "LongRunningQueryRiskRule",
    "LongTransactionWithoutSavepointRule",
    "MergeWithoutHoldlockRule",
    "MissingRetryLogicRule",
    "MissingRollbackRule",
    "NonIdempotentInsertRule",
    "NonIdempotentUpdateRule",
    "OnUpdateCascadeTimestampRule",
    "OracleAlterTableMoveWithoutRebuildRule",
    "OrphanRecordRiskRule",
    "PrestoInsertOverwriteWithoutPartitionRule",
    "ReadModifyWriteLockingRule",
    "ReplaceIntoRule",
    "SparkOverwriteWithoutPartitionRule",
    "SqliteDropColumnRule",
    "StaleReadRiskRule",
    "TOCTOUPatternRule",
    "TruncateInTryWithoutCatchRule",
    "TruncateWithoutTransactionRule",
    "UnsafeWriteRule",
    "Utf8InsteadOfUtf8mb4Rule",
]
