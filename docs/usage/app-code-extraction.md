# Application Code SQL Extraction

SlowQL extracts SQL strings from application source code and analyzes them with the same rules applied to `.sql` files.

## Supported Languages

| Language | Extensions | Extraction Method |
|----------|-----------|-------------------|
| Python | `.py` | Triple-quoted strings, f-strings, single/double-quoted strings |
| TypeScript/JavaScript | `.ts`, `.js`, `.tsx`, `.jsx` | Template literals, sink-aware regex |
| Java | `.java` | `prepareStatement()`, `createNativeQuery()` |
| Kotlin | `.kt` | `prepareStatement()`, `createNativeQuery()` |
| Go | `.go` | `db.Query()`, `db.Exec()` |
| Ruby | `.rb` | `connection.execute()`, `find_by_sql()`, heredocs |
| C# | `.cs` | `connection.Execute()` |
| MyBatis XML | `.xml` | Full XML parser with dynamic tag support |

## How Extraction Works

SlowQL identifies SQL sink functions for each language and extracts the string arguments.

### Python

```python
# Extracted as SQL
cursor.execute("SELECT id FROM users WHERE active = true")

# f-strings are extracted and marked as dynamic
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Triple-quoted strings
query = """
    DELETE FROM sessions
    WHERE expires_at < NOW()
"""
```

### TypeScript/JavaScript

``` TypeScript
// db.query() and pool.query() are recognized sinks
const result = await db.query("SELECT * FROM orders WHERE id = $1", [id]);

// Template literals are marked as dynamic
const result = await db.query(`SELECT * FROM ${table} WHERE id = $1`);

// knex.raw() is recognized
const rows = await knex.raw("SELECT id FROM users WHERE email = ?", [email]);
```

### Go

``` Go
// db.Query() and db.Exec() are recognized
rows, err := db.Query("SELECT id FROM users WHERE active = true")

// Format strings with %s or %v are marked as dynamic
query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1", tableName)
rows, err := db.Query(query, id)
```

### Ruby

``` Ruby
# connection.execute() and find_by_sql() are recognized
User.find_by_sql("SELECT * FROM users WHERE active = 1")

# Heredoc SQL
connection.execute(<<~SQL
  DELETE FROM sessions WHERE expires_at < NOW()
SQL
)

# Interpolation is marked as dynamic
connection.execute("SELECT * FROM users WHERE id = #{user_id}")
```

## Dynamic SQL Detection

When SlowQL detects string interpolation, format verbs, or template placeholders, it marks the extracted query as `is_dynamic`. This affects rule analysis:

- Dynamic queries are demoted from proven to contextual confidence.
- Injection rules (`SEC-INJ-001`) are specifically designed to flag dynamic construction.

## JPQL Filtering
Java queries using JPQL (Java Persistence Query Language) with entity class names like `UserEntity` are automatically detected and filtered out. SlowQL only analyzes queries targeting actual database tables.

``` Java
// Filtered out (JPQL)
em.createQuery("SELECT u FROM UserEntity u WHERE u.id = :id");

// Analyzed (SQL)
em.createNativeQuery("SELECT id FROM users WHERE id = ?");
```

## Inline Suppression in Application Code

Suppression comments work in application code too:

``` Python
# Python
query = "SELECT * FROM archive"  # slowql-disable-line PERF-SCAN-001

# TypeScript
const q = "DELETE FROM temp_data";  // slowql-disable-line REL-DATA-001
```

## Usage

``` Bash
# Scan Python application directory
slowql src/

# Scan specific file
slowql src/services/user_service.py

# Scan with schema validation
slowql src/ --schema db/schema.sql
```


