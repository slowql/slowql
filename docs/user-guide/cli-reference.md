# CLI Reference

The SlowQL command-line interface provides flexible options for analyzing SQL queries. This page lists all available commands and flags.

---

## ⚙️ Basic Usage

Run SlowQL with a file:

```Bash
slowql --input-file queries.sql
```

---

## 🚀 Common Flags

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| --fast           | Enables fast analysis mode                       |
| --no-intro       | Skips intro animation (ideal for CI/CD)          |
| --input-file     | Specifies the SQL file to analyze                |
| --export         | Sets export format (json, csv, html)             |
| --output         | Path to save exported results                    |
| --paste          | Opens interactive paste mode                     |
| --verbose        | Prints detailed logs                             |

---

## 📤 Export Examples

```Bash
slowql --input-file queries.sql --export json --output results.json
```

```Bash
slowql --input-file queries.sql --export html --output report.html
```

---

## 🧪 Verify Installation

```Bash
slowql --version
```
---

## 🔗 Related Pages

- [Interactive Mode](interactive-mode.md)
- [File Analysis](file-analysis.md)
- [Export Formats](export-formats.md)
- [CI/CD Integration](ci-cd-integration.md)
