from __future__ import annotations

"""
Reliability rules module.
"""

from .data_safety import *
from .deadlocks import *
from .error_handling import *
from .foreign_keys import *
from .idempotency import *
from .race_conditions import *
from .timeouts import *
from .transactions import *

__all__ = [
    'AlterTableDestructiveRule',
    'AutocommitDisabledRule',
    'CascadeDeleteRiskRule',
    'DeadlockPatternRule',
    'DropTableRule',
    'ExceptionSwallowedRule',
    'LockEscalationRiskRule',
    'LongRunningQueryRiskRule',
    'LongTransactionWithoutSavepointRule',
    'MissingRetryLogicRule',
    'MissingRollbackRule',
    'NonIdempotentInsertRule',
    'NonIdempotentUpdateRule',
    'OrphanRecordRiskRule',
    'ReadModifyWriteLockingRule',
    'StaleReadRiskRule',
    'TOCTOUPatternRule',
    'TruncateWithoutTransactionRule',
    'UnsafeWriteRule',
]
