# First Analysis

With SlowQL installed and configured, you are ready to run your first analysis. This page demonstrates how to analyze SQL queries using different modes and interpret the results.

---

## 🔍 Analyze a SQL File

The most common workflow is analyzing a file containing queries:

```Bash
slowql --input-file queries.sql --fast
```
This runs a quick analysis on all queries in `queries.sql`.

---

## 🧠 Interactive Paste Mode

If you want to test a single query quickly, use paste mode:

```Bash
slowql --paste
```
Paste your SQL directly into the terminal when prompted. SlowQL will analyze it immediately.

---

## 📤 Export Results

You can export analysis results to different formats for reporting or automation:

```Bash
slowql --input-file queries.sql --export json --output results.json
```
Supported formats: `json`, `csv`, `html`.

---

## 🛠️ CI/CD Safe Mode

For automated pipelines, disable animations and run fast mode:

```Bash
slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```
This ensures clean logs and machine‑readable output.

---

## 📈 Interpreting Results

SlowQL categorizes findings by severity:

- **Critical**: Queries that can cause severe performance or security issues.
- **High**: Queries likely to degrade performance significantly.
- **Medium**: Queries with moderate inefficiencies.
- **Low**: Minor issues or style warnings.

Results are displayed in the terminal and optionally exported.

---

## 🔗 Related Pages

- [Installation](installation.md)
- [Configuration](configuration.md)
- [CLI Reference](../user-guide/cli-reference.md)
- [Detectors Overview](../detectors/overview.md)
