# Medium Severity Detectors

Medium severity detectors highlight SQL patterns that may cause inefficiencies or readability issues. These are not immediately dangerous but should be corrected to maintain performance and clarity.

---

## 📦 SELECT *

Detects queries that use `SELECT *` instead of specifying columns.

```Bash
SELECT * FROM customers;
```

**Suggestion**: Explicitly list required columns to reduce overhead and improve clarity.

---

## 🔄 Non-SARGable Expressions

Flags queries that use functions on indexed columns, preventing index usage.

```Bash
SELECT * FROM orders WHERE YEAR(order_date) = 2023;
```

**Suggestion**: Rewrite conditions to preserve index usage, e.g. `order_date >= '2023-01-01'`.

---

## 🧩 Nested Subqueries

Detects deeply nested subqueries that can be rewritten as joins.

```Bash
SELECT * FROM customers WHERE id IN (SELECT customer_id FROM orders);
```

**Suggestion**: Use a JOIN instead of a nested subquery for better performance.

---

## 🧠 Why It Matters

Medium severity issues can:
- Reduce query efficiency
- Increase resource usage under load
- Make queries harder to maintain
- Lead to performance bottlenecks in larger datasets

---

## 🔗 Related Pages

- [High Severity Detectors](high-severity.md)  
- [Low Severity Detectors](low-severity.md)  
- [Overview](overview.md)  
