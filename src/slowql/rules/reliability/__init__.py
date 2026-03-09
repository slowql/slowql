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
    'UnsafeWriteRule',
    'DropTableRule',
    'TruncateWithoutTransactionRule',
    'AlterTableDestructiveRule',
    'DeadlockPatternRule',
    'LockEscalationRiskRule',
    'ExceptionSwallowedRule',
    'LongTransactionWithoutSavepointRule',
    'OrphanRecordRiskRule',
    'CascadeDeleteRiskRule',
    'NonIdempotentInsertRule',
    'NonIdempotentUpdateRule',
    'ReadModifyWriteLockingRule',
    'TOCTOUPatternRule',
    'LongRunningQueryRiskRule',
    'StaleReadRiskRule',
    'MissingRetryLogicRule',
    'MissingRollbackRule',
    'AutocommitDisabledRule',
]
