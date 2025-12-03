# High Severity Detectors

High severity detectors identify SQL patterns that pose serious performance or maintainability risks. These issues should be fixed promptly to avoid degraded performance, data inconsistencies, or exposure to unsafe practices.

---

## ⚡ SELECT *

Detects queries that retrieve all columns without explicit selection.

```Bash
SELECT * FROM users;
```

**Suggestion**: Specify only the required columns to reduce load and improve clarity.

---

## 📊 Cartesian Joins

Flags joins without proper conditions that can explode result sets.

```Bash
SELECT * FROM users, orders;
```

**Suggestion**: Always include explicit JOIN conditions to avoid unintended cross products.

---

## 🌀 Nested Subqueries

Detects deeply nested subqueries that can cause performance bottlenecks.

```Bash
SELECT * FROM users WHERE id IN (SELECT id FROM orders WHERE id IN (SELECT id FROM payments));
```

**Suggestion**: Refactor into JOINs or temporary tables for efficiency.

---

## 🧱 Non-Indexed WHERE Clauses

Flags queries filtering on columns without indexes.

```Bash
SELECT * FROM orders WHERE status = 'pending';
```

**Suggestion**: Add indexes to frequently queried columns.

---

## 🧠 Why It Matters

High severity issues can:
- Cause severe performance degradation under load  
- Increase resource consumption and query latency  
- Lead to data inconsistencies or maintenance headaches  
- Block scalability in enterprise environments  

---

## 🔗 Related Pages

- [Critical Detectors](critical-detectors.md)  
- [Overview](overview.md)  
- [Best Practices](../security/best-practices.md)  
