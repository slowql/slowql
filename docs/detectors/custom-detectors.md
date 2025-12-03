# Custom Detectors

SlowQL allows you to define your own detectors to enforce team‑specific rules or catch patterns unique to your environment. This page explains how to create and configure custom detectors.

---

## 🛠 Why Custom Detectors?

Built‑in detectors cover common performance and security issues, but you may want to:
- Flag queries using non‑approved functions
- Enforce naming conventions
- Catch dialect‑specific anti‑patterns
- Extend SlowQL for specialized workloads

---

## 📂 Detector Definition File

Custom detectors are defined in a `.slowql.toml` file or a separate configuration file.

```toml
[detectors.select_star]
category = "performance"
severity = "medium"
message = "Avoid SELECT * for clarity and performance."
suggestion = "Specify column names explicitly."
```

---

## ⚙️ Example: Enforcing Naming Conventions

```toml
[detectors.bad_table_name]
category = "style"
severity = "low"
message = "Table names must be lowercase with underscores."
suggestion = "Rename table to follow convention."
```

---

## 🚀 Running with Custom Detectors

Run SlowQL with your config file:

```Bash
slowql --input-file queries.sql --config .slowql.toml
```

---

## 📤 Exporting Results

Custom detector findings appear alongside built‑in detectors in JSON, CSV, or HTML exports.

```Bash
slowql --input-file queries.sql --export json --output results.json
```

---

## 🧠 Best Practices

- Keep detector definitions small and focused  
- Use consistent severity levels across custom and built‑in detectors  
- Document custom rules so teams understand why they exist  
- Version control your `.slowql.toml` to track changes  

---

## 🔗 Related Pages

- [Critical Detectors](critical-detectors.md)  
- [High Severity Detectors](high-severity.md)  
- [Medium Severity Detectors](medium-severity.md)  
- [Low Severity Detectors](low-severity.md)  
- [Overview](overview.md)  
