# XML/XPath Injection (SEC-INJ-009)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
XPath injection allows attackers to manipulate XML queries, bypass authentication, and extract unauthorized data from XML documents. Similar to SQL injection but for XML.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use parameterized XPath/XQuery. Escape XML special characters: < > & ' ". Validate against schema. Use XPath variables instead of concatenation. Example: use $variable in XPath, not string concatenation.
