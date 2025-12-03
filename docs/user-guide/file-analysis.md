# File Analysis

SlowQL can analyze entire SQL files, making it easy to review multiple queries at once. This page explains how to run file analysis and interpret the results.

---

## 📂 Analyze a File

Run SlowQL on a file containing queries:

```Bash
slowql --input-file queries.sql
```

This will analyze all queries in `queries.sql` and display findings in the terminal.

---

## ⚡ Fast Mode

Use fast mode for quicker results:

```Bash
slowql --fast --input-file queries.sql
```

Fast mode skips deep checks but still highlights critical issues.

---

## 🛠️ CI/CD Safe Mode

For automated pipelines, disable animations and export results:

```Bash
slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```

This ensures clean logs and machine‑readable output.

---

## 📤 Export Results

You can export analysis results to different formats:

```Bash
slowql --input-file queries.sql --export html --output report.html
```
Supported formats: `json`, `csv`, `html`.

---

## 📈 Interpreting Results

SlowQL categorizes findings by severity:

- **Critical** → Queries that can cause severe performance or security issues  
- **High** → Queries likely to degrade performance significantly  
- **Medium** → Queries with moderate inefficiencies  
- **Low** → Minor issues or style warnings  

---

## 🔗 Related Pages

- [CLI Reference](cli-reference.md)  
- [Interactive Mode](interactive-mode.md)  
- [Export Formats](export-formats.md)  
- [CI/CD Integration](ci-cd-integration.md)  
