# Low Severity Detectors

Low severity detectors highlight minor issues or stylistic inconsistencies in SQL queries. These do not usually impact performance but are useful for maintaining clean, readable, and consistent code.

---

## ✍️ Inconsistent Casing

Detects queries that mix uppercase and lowercase keywords.

```Bash
select Id, Name from Customers;
```

**Suggestion**: Use consistent casing, e.g. `SELECT id, name FROM customers;`.

---

## 🗑 Deprecated Syntax

Flags use of outdated SQL constructs that may not be supported in future versions.

```Bash
SELECT TOP 10 * FROM orders;
```

**Suggestion**: Use `LIMIT` or `FETCH FIRST` depending on your SQL dialect.

---

## 📐 Unnecessary Aliases

Detects redundant aliases that add noise without improving clarity.

```Bash
SELECT c.id FROM customers c;
```

**Suggestion**: Remove aliases unless they improve readability in complex queries.

---

## 🧠 Why It Matters

Low severity issues can:
- Reduce readability and maintainability
- Cause confusion in team environments
- Lead to inconsistent coding standards
- Make migration to new SQL dialects harder

---

## 🔗 Related Pages

- [Medium Severity Detectors](medium-severity.md)  
- [Custom Detectors](custom-detectors.md)  
- [Overview](overview.md)  
