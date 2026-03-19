# DO Block Without LANGUAGE (QUAL-PG-001)

**Dimension**: Quality
**Severity**: Low
**Scope**: Dialect Specific (Postgresql)

## Description
Implicit language defaults reduce code clarity and can cause errors if the default language changes or if plpgsql is not loaded.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LANGUAGE plpgsql: DO $$ BEGIN ... END $$ LANGUAGE plpgsql;
