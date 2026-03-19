# User Creation Without Password (SEC-AUTH-003)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Passwordless database accounts can be accessed by anyone who knows the username, enabling unauthorized data access, modification, or administrative actions.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify a strong password when creating users or logins. Use IDENTIFIED BY (Oracle/MySQL), WITH PASSWORD (SQL Server), or PASSWORD (PostgreSQL). Enforce password complexity policies.
