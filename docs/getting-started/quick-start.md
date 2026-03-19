# Quick Start

Welcome to SlowQL! This guide catapults you from zero to executing an automated, static SQL review capable of remediating critical database flaws natively.

## 1. Install SlowQL

Assuming you have `Python 3.11+` actively available, bootstrap the entire suite via pip:

```bash
pip install "slowql[all]"
```

## 2. Initialize the Workspace

Navigate to the absolute root directory of your repository, and execute the wizard sequence.

```bash
slowql --init
```

The CLI tool will dynamically prompt you for fundamental criteria (e.g. `postgresql`, `mysql`, `snowflake` grammar preferences), automatically constructing a `slowql.yaml` or `pyproject.toml` profile.

## 3. Analyze Code

Create a file named `unprotected_query.sql` representing a dangerous migration:

```sql
SELECT * FROM users;

-- Extremely dangerous omission
DELETE FROM orders; 
```

Point the execution engine directly at the file:

```bash
slowql unprotected_query.sql
```

### Analyzing the Report
By default, SlowQL evaluates exactly 272 potential failure cases. The Cyberpunk Console UI will halt execution and render:

- **PERF-SCAN-001 (Performance):** A strict advisory identifying the `SELECT *` operation highlighting catastrophic IO scaling logic.
- **REL-DATA-001 (Reliability/Critical):** An absolute blocker identifying a naked `DELETE` statement absent a `WHERE` guard—representing an unqualified destruction of an entire data cluster.

## 4. Run Auto-Fixes

SlowQL refuses to just complain; it repairs logic securely utilizing `RemediationMode.SAFE_APPLY` AST transforms. 

**Preview the mathematical layout changes (via git-diff format):**
```bash
slowql unprotected_query.sql --diff
```

**Overwriting the file directly (with `.bak` backup creation natively):**
```bash
slowql unprotected_query.sql --fix
```

## Next Steps

You've successfully instantiated and cleared an enterprise analysis pipeline. 
- Advance to [Configuration](configuration.md) to explore the PyDantic tuning limits.
- Learn to deploy the engine inside [GitHub Actions](../usage/ci-cd-integration.md).
- Hook SlowQL into your active text editor: [Editor Setup](../usage/editor-setup.md).
