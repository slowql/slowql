# Configuration

After installing SlowQL, you can customize its behavior using command-line flags, environment variables, and optional config files. This guide walks through the most common configuration options for local use and CI/CD pipelines.

---

## ⚙️ CLI Flags

SlowQL supports a variety of flags to control analysis behavior:

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| --fast           | Enables fast analysis mode                       |
| --no-intro       | Skips intro animation (ideal for CI/CD)          |
| --input-file     | Specifies the SQL file to analyze                |
| --export         | Sets export format (json, csv, html)             |
| --output         | Path to save exported results                    |
| --paste          | Opens interactive paste mode                     |

```Bash
slowql --fast --input-file queries.sql --export json --output results.json
```

---

## 🌐 Environment Variables

You can set environment variables to control default behavior:

| Variable               | Purpose                                  | Example Value       |
|------------------------|------------------------------------------|---------------------|
| SLOWQL_DEFAULT_EXPORT  | Default export format                    | json                |
| SLOWQL_NO_INTRO        | Disable intro animation globally         | 1                   |

```Bash
export SLOWQL_DEFAULT_EXPORT=json
export SLOWQL_NO_INTRO=1
```
---

## 📄 Optional Config File

SlowQL can read a .slowql.toml config file from your project root.

```TOML
[defaults]
export = "json"
no_intro = true
```
This allows you to standardize behavior across teams or CI environments.

---

## 🧪 Verify Configuration

Run SlowQL with verbose output to confirm your settings:

```Bash
slowql --input-file queries.sql --export json --output results.json --verbose
```
---

## 🔗 Related Pages

- [Installation](installation.md)
- [First Analysis](first-analysis.md)
- [CLI Reference](../user-guide/cli-reference.md)
