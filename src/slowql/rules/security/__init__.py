from __future__ import annotations

"""
Security rules module.
"""

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
    'HardcodedPasswordRule',
    'GrantAllRule',
    'GrantToPublicRule',
    'UserCreationWithoutPasswordRule',
    'PasswordPolicyBypassRule',
    'PrivilegeEscalationRoleGrantRule',
    'SchemaOwnershipChangeRule',
    'HorizontalAuthorizationBypassRule',
    'OSCommandInjectionRule',
    'PathTraversalRule',
    'LocalFileInclusionRule',
    'SSRFViaDatabaseRule',
    'DangerousServerConfigRule',
    'OverprivilegedExecutionContextRule',
    'HardcodedCredentialsRule',
    'WeakSSLConfigRule',
    'DefaultCredentialUsageRule',
    'OverlyPermissiveAccessRule',
    'WeakHashingAlgorithmRule',
    'PlaintextPasswordInQueryRule',
    'HardcodedEncryptionKeyRule',
    'WeakEncryptionAlgorithmRule',
    'DataExfiltrationViaFileRule',
    'RemoteDataAccessRule',
    'UnboundedRecursiveCTERule',
    'RegexDenialOfServiceRule',
    'DatabaseVersionDisclosureRule',
    'SchemaInformationDisclosureRule',
    'TimingAttackPatternRule',
    'VerboseErrorMessageDisclosureRule',
    'SQLInjectionRule',
    'DynamicSQLExecutionRule',
    'TautologicalOrConditionRule',
    'TimeBasedBlindInjectionRule',
    'SecondOrderSQLInjectionRule',
    'LikeWildcardInjectionRule',
    'LDAPInjectionRule',
    'NoSQLInjectionRule',
    'XMLXPathInjectionRule',
    'ServerSideTemplateInjectionRule',
    'JSONFunctionInjectionRule',
    'SensitiveDataInErrorOutputRule',
    'AuditTrailManipulationRule',
    'InsecureSessionTokenStorageRule',
    'SessionTimeoutNotEnforcedRule',
]
