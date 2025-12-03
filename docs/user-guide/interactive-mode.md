# Interactive Mode

SlowQL provides an interactive paste mode for quickly testing individual queries without needing a file. This is ideal for ad‑hoc analysis or teaching scenarios.

---

## 🧠 Start Interactive Mode

Launch interactive mode with:

```Bash
slowql --paste
```

You’ll be prompted to paste a SQL query directly into the terminal. SlowQL will analyze it immediately.

---

## 🎯 Example Session

```Bash
slowql --paste
> SELECT * FROM users WHERE email LIKE '%@gmail.com';
```

SlowQL will return analysis results for the pasted query, including performance warnings and detector findings.

---

## ⚙️ Options in Interactive Mode

- **--fast** → Run quick analysis without deep checks  
- **--no-intro** → Skip animations for clean CI/CD logs  
- **--export json** → Save results to a JSON file  

Example:

```Bash
slowql --paste --fast --export json --output single-query.json
```

---

## 📋 Use Cases

- Teaching SQL optimization in workshops  
- Quickly testing queries before committing them to source code  
- Debugging performance issues without creating a file  

---

## 🔗 Related Pages

- [CLI Reference](cli-reference.md)  
- [File Analysis](file-analysis.md)  
- [Export Formats](export-formats.md)  
