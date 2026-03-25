# Application Code SQL Extraction

SlowQL can automatically extract and analyze SQL strings embedded within application code. This allows you to catch SQL vulnerabilities and performance issues directly in your application source files, even when the SQL isn't stored in standalone `.sql` files.

## Supported Languages

SlowQL currently supports SQL extraction from:

- **Python** (via AST analysis)
- **TypeScript & JavaScript** (via regex)
- **Java** (via regex)
- **Go** (via regex)
- **Ruby** (via regex)

## How it Works

When you run SlowQL on a directory or a specific application file, it detects the file extension and applies the appropriate extraction logic.

### Python AST Analysis

For Python, SlowQL uses the `ast` module to perform precise extraction. It can identify:
- Static string constants
- f-strings (dynamic parts are masked with `__dynamic__` to allow parsing)
- Multi-line strings (triple quotes)

### Regex-based Extraction

For other languages, SlowQL uses optimized regular expressions to find string literals that look like SQL queries (e.g., starting with `SELECT`, `INSERT`, `UPDATE`, etc.).

## Dynamic SQL Detection

One of the most powerful features of the extraction engine is the ability to identify **dynamic SQL**. 

When SlowQL finds an f-string in Python or a template literal in TypeScript, it flags the resulting query as `is_dynamic`. This information is then used by the security rules (like `SEC-INJ-001`) to automatically flag the query as a potential SQL injection risk, as it's being constructed using string interpolation rather than parameterized inputs.

## Usage

Simply pass the application files or directories to the `slowql` command:

```bash
slowql src/app.py src/services/
```

SlowQL will output issues found within those files, including precise line and column numbers.

### Example (Python)

```python
# src/db.py
def get_user(user_id):
    # SlowQL will flag this line for SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
```

Running SlowQL:

```bash
$ slowql src/db.py

src/db.py:4:5: SEC-INJ-001: Potential SQL injection: Query is dynamically constructed (e.g., f-string or template literal).
```

## Inline Suppression

You can use standard SlowQL suppression comments within your application code to silence specific rules:

```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # slowql-disable-line SEC-INJ-001
```
