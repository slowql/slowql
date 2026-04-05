# First Analysis

With SlowQL installed and configured, you are ready to execute your first static validation. This guide demonstrates how to analyze SQL queries across multiple execution modes and strictly interpret the resulting telemetry.

---

## Analyze a SQL File

The fundamental workflow involves passing a SQL file (or an entire directory) directly to the engine:

```bash
slowql queries.sql --fast
```
The `--fast` flag disables terminal intro animations to accelerate the return of the analysis payload.

---

## Interactive Paste Mode

If you need to rapidly benchmark a floating query snippet outside of a file structure, utilize the clipboard mode:

```bash
slowql --mode paste
```
SlowQL will temporarily hand over STDIN, allowing you to paste your SQL payload directly into the terminal buffer for immediate parsing.

---

## Export Results

For auditing, compliance trails, or downstream security integrations, export your findings to standard serialization formats:

```bash
slowql queries.sql --export json sarif --out build/reports/
```
**Supported Formats:** `json`, `csv`, `html`, `sarif`.
SlowQL will drop the respective serialized payloads (e.g. `slowql_report.json`) into the target `--out` directory while still printing the console summary.

---

## CI/CD Safe Mode

When running strictly within a headless environment or GitHub Action, it is critical to lock down the UI and prevent pipeline hangups:

```bash
slowql src/ --fail-on high --format github-actions --export sarif --out artifacts/
```
- `--non-interactive`: Extraneous when `<file>` arguments are provided, as SlowQL now defaults to non-interactive mode immediately to guarantee CI/CD safety by bypassing UI elements and dialect selectors.
- `--fail-on high`: Instructs the engine to exit with a non-zero status code if `High` or `Critical` flaws are detected, failing the pipeline run natively.

---

## Interpreting Results

SlowQL mathematically scores identified vulnerabilities across exactly four impact strata:

- **Critical:** Absolute blockers. Expected to trigger catastrophic data losses (`DELETE` without `WHERE`) or severe security exfiltration vectors.
- **High:** Severe structural flaws guaranteeing latency degradation or non-compliance (missing critical indices on joined properties).
- **Medium:** Suboptimal technical debt. Valid but excessively expensive querying patterns (e.g. nested subqueries instead of `CTEs`, arbitrary `SELECT *`).
- **Low:** Aesthetic drift, stylistic non-conformity, or minute optimizations.

---

## Related Documentation

- [Installation](installation.md): Review global vs Docker deployment strategies.
- [Configuration](configuration.md): Define ruleset boundaries inside `slowql.yaml`.
- [CLI Reference](../usage/cli-reference.md): Read the exhaustive engine argument list.
- [Rules Explorer](../rules/overview.md): Browse the granular 272 AST rules.
