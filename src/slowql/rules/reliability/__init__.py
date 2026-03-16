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
    "AlterTableDestructiveRule",
    "AutocommitDisabledRule",
    "CascadeDeleteRiskRule",
    "DeadlockPatternRule",
    "DropTableRule",
    "ExceptionSwallowedRule",
    "InsertIgnoreRule",
    "LockEscalationRiskRule",
    "LongRunningQueryRiskRule",
    "LongTransactionWithoutSavepointRule",
    "MissingRetryLogicRule",
    "MissingRollbackRule",
    "NonIdempotentInsertRule",
    "NonIdempotentUpdateRule",
    "OrphanRecordRiskRule",
    "ReadModifyWriteLockingRule",
    "ReplaceIntoRule",
    "StaleReadRiskRule",
    "TOCTOUPatternRule",
    "TruncateWithoutTransactionRule",
    "UnsafeWriteRule",
]
