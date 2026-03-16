"""
Reliability rules module.
"""

from __future__ import annotations

from .data_safety import *
from .deadlocks import *
from .error_handling import *
from .foreign_keys import *
from .idempotency import *
from .race_conditions import *
from .timeouts import *
from .transactions import *

__all__ = [
    "AlterTableAddColumnVolatileDefaultRule",
    "AlterTableDestructiveRule",
    "AtAtIdentityRule",
    "AutocommitDisabledRule",
    "BigQueryDmlWithoutWhereOnPartitionedRule",
    "CascadeDeleteRiskRule",
    "ConnectByWithoutNocycleRule",
    "CreateIndexWithoutConcurrentlyRule",
    "DeadlockPatternRule",
    "DropTableRule",
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
    "ReadModifyWriteLockingRule",
    "ReplaceIntoRule",
    "StaleReadRiskRule",
    "TOCTOUPatternRule",
    "TruncateInTryWithoutCatchRule",
    "TruncateWithoutTransactionRule",
    "UnsafeWriteRule",
    "Utf8InsteadOfUtf8mb4Rule",
]
