# Detectors Overview

SlowQL uses detectors to identify common performance and security issues in SQL queries. Each detector focuses on a specific pattern that can cause inefficiency or risk. This section introduces the detectors and links to detailed pages for each.

---

## 🔍 What Are Detectors?

Detectors are built‑in rules that scan queries for problematic constructs. They provide:

- **Name** → Short identifier for the detector  
- **Category** → Performance, Security, or Style  
- **Severity** → Critical, High, Medium, Low  
- **Message** → Explanation of the issue  
- **Suggestion** → Recommended fix or alternative  

---

## 📂 Detector Categories

- **Performance Detectors** → Catch slow patterns like `SELECT *`, missing indexes, or unbounded scans  
- **Security Detectors** → Identify risks such as SQL injection or unsafe string concatenation  
- **Style Detectors** → Enforce best practices like consistent casing or avoiding deprecated syntax  

---

## ⚡ Example Output

```Bash
slowql --input-file queries.sql --export json --output results.json
```

Sample detector output (JSON):

```code
{
  "detector": "select_star",
  "category": "performance",
  "severity": "medium",
  "message": "Avoid SELECT * for better performance and clarity.",
  "suggestion": "Specify column names explicitly."
}
```

---

## 📖 Detector Pages

- [Critical Detectors](critical-detectors.md)  
- [High Severity](high-severity.md)  
- [Meduim Severity](meduim-severity.md)  
- [Low Severity](low-severity.md)
- [Custom Detectors](custom-detectors.md)

---

## 🔗 Related Pages

- [CLI Reference](../user-guide/cli-reference.md)  
- [File Analysis](../user-guide/file-analysis.md)  
