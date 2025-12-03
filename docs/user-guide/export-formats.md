# Export Formats

SlowQL can export analysis results into multiple formats for reporting, automation, or integration with other tools. This page explains the supported formats and how to use them.

---

## 📊 JSON Export

Export results to JSON for machine‑readable output:

```Bash
slowql --input-file queries.sql --export json --output results.json
```

This format is ideal for CI/CD pipelines or further processing with scripts.

---

## 📑 CSV Export

Export results to CSV for spreadsheet analysis:

```Bash
slowql --input-file queries.sql --export csv --output results.csv
```

This format is useful for data analysis in Excel, Google Sheets, or other tools.

---

## 🌐 HTML Export

Export results to HTML for human‑readable reports:

```Bash
slowql --input-file queries.sql --export html --output report.html
```

This format is ideal for sharing results with teams or publishing reports.

---

## ⚙️ Default Export Format

You can set a default export format using environment variables or config files:

```toml
[defaults]
export = "json"
```

```Bash
export SLOWQL_DEFAULT_EXPORT=json
```

---

## 📋 Combining Options

You can combine export options with other flags:

```Bash
slowql --fast --no-intro --input-file queries.sql --export json --output results.json
```

---

## 🔗 Related Pages

- [CLI Reference](cli-reference.md)  
- [File Analysis](file-analysis.md)  
- [CI/CD Integration](ci-cd-integration.md)  
