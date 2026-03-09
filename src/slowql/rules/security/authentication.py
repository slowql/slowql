from __future__ import annotations

"""
Security Authentication rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'GrantAllRule',
    'GrantToPublicRule',
    'HardcodedPasswordRule',
    'PasswordPolicyBypassRule',
    'UserCreationWithoutPasswordRule',
]


class HardcodedPasswordRule(PatternRule):
    """Detects hardcoded passwords in queries."""

    id = "SEC-AUTH-001"
    name = "Hardcoded Password"
    description = "Detects plain-text passwords assigned in SQL queries."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"(password|passwd|pwd|secret|token)\s*=\s*'[^']+'"
    message_template = "Hardcoded credential detected: {match}"

    impact = "Credentials exposed in source code or logs can be used by attackers."
    rationale = "Secrets should never be stored in plain text within code or queries."
    fix_guidance = "Use query parameters and secrets management."


class GrantAllRule(ASTRule):
    """Detects GRANT ALL permissions."""

    id = "SEC-AUTH-005"
    name = "Excessive Privileges (GRANT ALL)"
    description = "Detects GRANT ALL statements which violate least privilege."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        # SQLGlot parses GRANT specifically
        if isinstance(ast, exp.Grant):
            # Use getattr to safely access 'actions' without triggering static analysis errors
            raw_actions = getattr(ast, "actions", None) or []
            normalized_actions = []

            for action in raw_actions:
                # Handle Identifier/Var nodes vs raw strings if any
                if hasattr(action, "name"):
                    normalized_actions.append(action.name.upper())
                else:
                    normalized_actions.append(str(action).upper())

            if "ALL" in normalized_actions or "ALL PRIVILEGES" in normalized_actions:
                issues.append(
                    self.create_issue(
                        query=query,
                        message="GRANT ALL detected. Follow principle of least privilege.",
                        snippet=query.raw,
                        impact="Users receive administrative control, increasing blast radius of "
                        "compromise.",
                    )
                )

        return issues


class GrantToPublicRule(PatternRule):
    """Detects GRANT statements to the PUBLIC role."""

    id = "SEC-AUTH-002"
    name = "Grant to PUBLIC Role"
    description = (
        "Detects GRANT statements that assign permissions to the PUBLIC role. PUBLIC "
        "includes every user in the database, making this a violation of the "
        "least-privilege principle."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"\bGRANT\b.+\bTO\s+PUBLIC\b"
    message_template = "Grant to PUBLIC role detected: {match}"

    impact = (
        "Granting permissions to PUBLIC gives every current and future database user "
        "access to the specified objects, creating an uncontrollable access surface "
        "and potential data exposure."
    )
    fix_guidance = (
        "Grant permissions to specific roles or users instead of PUBLIC. Create "
        "application-specific roles with minimal required permissions and assign "
        "users to those roles."
    )


class UserCreationWithoutPasswordRule(PatternRule):
    """Detects CREATE USER/LOGIN without a password clause."""

    id = "SEC-AUTH-003"
    name = "User Creation Without Password"
    description = (
        "Detects CREATE USER and CREATE LOGIN statements that do not include a "
        "password clause (IDENTIFIED BY, WITH PASSWORD, PASSWORD =). Creating "
        "database users without passwords creates unauthenticated access points."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"\bCREATE\s+(USER|LOGIN)\b(?![\s\S]*(IDENTIFIED\s+BY|WITH\s+PASSWORD|PASSWORD\s*=))"
    message_template = "User/login created without password: {match}"

    impact = (
        "Passwordless database accounts can be accessed by anyone who knows the "
        "username, enabling unauthorized data access, modification, or administrative "
        "actions."
    )
    fix_guidance = (
        "Always specify a strong password when creating users or logins. Use "
        "IDENTIFIED BY (Oracle/MySQL), WITH PASSWORD (SQL Server), or PASSWORD "
        "(PostgreSQL). Enforce password complexity policies."
    )


class PasswordPolicyBypassRule(PatternRule):
    """Detects disabling of password policy enforcement."""

    id = "SEC-AUTH-004"
    name = "Password Policy Bypass"
    description = (
        "Detects disabling of password policy enforcement (CHECK_POLICY = OFF) or "
        "password expiration checks (CHECK_EXPIRATION = OFF) in SQL Server login "
        "management. Disabling these allows weak and non-expiring passwords."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = (
        r"\bCHECK_POLICY\s*=\s*OFF\b"
        r"|\bCHECK_EXPIRATION\s*=\s*OFF\b"
    )
    message_template = "Password policy bypass detected: {match}"

    impact = (
        "Weak passwords without policy enforcement are vulnerable to brute force and "
        "credential stuffing attacks. Non-expiring passwords increase the window for "
        "compromised credentials to be exploited."
    )
    fix_guidance = (
        "Always keep CHECK_POLICY = ON and CHECK_EXPIRATION = ON. Use strong password "
        "complexity requirements. Implement password rotation policies through "
        "database-level enforcement."
    )
