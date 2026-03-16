"""
Security rules module.
"""

from __future__ import annotations

from .authentication import *
from .authorization import *
from .command import *
from .configuration import *
from .cryptography import *
from .data_protection import *
from .dos import *
from .information import *
from .injection import *
from .logging import *
from .session import *

__all__ = [
    "AuditTrailManipulationRule",
    "DangerousServerConfigRule",
    "DataExfiltrationViaFileRule",
    "DatabaseVersionDisclosureRule",
    "DefaultCredentialUsageRule",
    "DynamicSQLExecutionRule",
    "GrantAllRule",
    "GrantToPublicRule",
    "HardcodedCredentialsRule",
    "HardcodedEncryptionKeyRule",
    "HardcodedPasswordRule",
    "HorizontalAuthorizationBypassRule",
    "InsecureSessionTokenStorageRule",
    "JSONFunctionInjectionRule",
    "LDAPInjectionRule",
    "LikeWildcardInjectionRule",
    "LoadDataLocalInfileRule",
    "LocalFileInclusionRule",
    "NoSQLInjectionRule",
    "OSCommandInjectionPostgresRule",
    "OSCommandInjectionTsqlRule",
    "OpenRowsetRule",
    "OracleDbmsSqlInjectionRule",
    "OracleExecuteImmediateConcatRule",
    "OracleUtlAccessRule",
    "OverlyPermissiveAccessRule",
    "OverprivilegedExecutionContextRule",
    "PasswordPolicyBypassRule",
    "PathTraversalRule",
    "PgSleepUsageRule",
    "PlaintextPasswordInQueryRule",
    "PrivilegeEscalationRoleGrantRule",
    "RaiseNoticeInjectionRule",
    "RegexDenialOfServiceRule",
    "RemoteDataAccessRule",
    "SQLInjectionRule",
    "SSRFViaDatabaseRule",
    "SchemaInformationDisclosureRule",
    "SchemaOwnershipChangeRule",
    "SearchPathManipulationRule",
    "SecondOrderSQLInjectionRule",
    "SensitiveDataInErrorOutputRule",
    "ServerSideTemplateInjectionRule",
    "SessionTimeoutNotEnforcedRule",
    "SpOACreateRule",
    "TautologicalOrConditionRule",
    "TimeBasedBlindInjectionRule",
    "TimingAttackPatternRule",
    "UnboundedRecursiveCTERule",
    "UserCreationWithoutPasswordRule",
    "VerboseErrorMessageDisclosureRule",
    "WeakEncryptionAlgorithmRule",
    "WeakHashingAlgorithmRule",
    "WeakSSLConfigRule",
    "XMLXPathInjectionRule",
]
