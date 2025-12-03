# Quick Start

This page provides a fast path to running SlowQL immediately after installation. Follow these steps to analyze queries in under a minute.

---

## ⚡ Run Your First Command

```Bash
slowql --fast --input-file queries.sql
```
This analyzes all queries in `queries.sql` using fast mode.

---

## 🧠 Try Interactive Paste Mode

```Bash
slowql --paste
```
Paste a query directly into the terminal when prompted. SlowQL will analyze it instantly.

---

## 📤 Export Results

```Bash
slowql --input-file queries.sql --export html --output report.html
```
This saves results to an HTML report. Supported formats: `json`, `csv`, `html`.

---

## 🛠️ CI/CD Friendly Mode

```Bash
slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```
Use this in pipelines for clean logs and machine‑readable output.

---

## ✅ Verify Setup

```Bash
slowql --version
```
Confirm that SlowQL is installed and available.

---

## 🔗 Related Pages

- [Installation](installation.md)
- [Configuration](configuration.md)
- [First Analysis](first-analysis.md)
- [CLI Reference](../user-guide/cli-reference.md)
