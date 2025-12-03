# Critical Detectors

Critical detectors identify SQL patterns that pose severe performance or security risks. These issues should be addressed immediately before deploying to production.

---

## 🚨 SQL Injection Risk

Detects unsafe string concatenation that could allow user input to alter query logic.

```Bash
SELECT * FROM users WHERE email = '" + userInput + "';
```

**Suggestion**: Use parameterized queries or prepared statements.

---

## 🧨 Unbounded DELETE or UPDATE

Flags destructive queries that affect entire tables without a WHERE clause.

```Bash
DELETE FROM orders;
```

**Suggestion**: Always include a WHERE clause to scope the operation.

---

## 🔓 Unsafe Dynamic SQL

Detects use of EXEC or dynamic SQL construction without sanitization.

```Bash
EXEC('SELECT * FROM ' + tableName);
```

**Suggestion**: Validate and sanitize all dynamic inputs.

---

## 🧠 Why It Matters

Critical issues can:
- Expose sensitive data
- Corrupt or delete entire datasets
- Open attack surfaces for SQL injection
- Cause major outages under load

---

## 🔗 Related Pages

- [High Severity Detectors](high-severity.md)  
- [Overview](overview.md)  
