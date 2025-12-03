# Parser Engine

The SlowQL parser engine is responsible for transforming raw SQL text into an internal representation (AST) and running detectors against it. This enables static analysis without connecting to a database.

---

## 🧩 Architecture Overview

1. **Lexical Analysis (Tokenizer)**  
   Breaks SQL text into tokens (keywords, identifiers, operators, literals).

2. **Parsing into AST (Abstract Syntax Tree)**  
   Structures tokens into a tree that represents the logical components of the query.

3. **Detector Pipeline**  
   Runs built‑in and custom detectors against the AST to identify anti‑patterns.

4. **Severity Classification**  
   Assigns Critical, High, Medium, or Low severity to each finding.

5. **Report Generation**  
   Exports results in JSON, CSV, or HTML formats.

---

## ⚙️ Example Flow

```Bash
slowql --input-file queries.sql --export json --output results.json
```

Steps performed:
1. Tokenize queries in `queries.sql`  
2. Build AST for each query  
3. Run detectors → collect findings  
4. Classify severity → Critical/High/Medium/Low  
5. Export results to `results.json`

---

## 📊 Example Detector Output

# code
{
  "detector": "select_star",
  "category": "performance",
  "severity": "medium",
  "message": "Avoid SELECT * for better performance and clarity.",
  "suggestion": "Specify column names explicitly."
}

---

## 🛠 Extensibility

You can extend the parser engine with custom detectors defined in `.slowql.toml`:

# toml
[detectors.non_sargable]
category = "performance"
severity = "medium"
message = "Avoid functions on indexed columns."
suggestion = "Rewrite conditions to preserve index usage."

---

## 🔗 Related Pages

- [Overview](../detectors/overview.md)  
- [Critical Detectors](../detectors/critical-detectors.md)  
- [Custom Detectors](../detectors/custom-detectors.md)  
