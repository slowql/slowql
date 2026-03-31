# MyBatis XML Support

## Overview
MyBatis is a popular Java/Spring ORM framework that uses XML mapper files to define SQL statements. These mapper files allow developers to write raw SQL while keeping it separate from Java code. Static analysis of these XML files is essential to catch security, performance, and quality issues before they reach production.

SlowQL now includes a **MyBatis XML extractor** (`src/slowql/parser/mybatis.py`) that parses mapper files, extracts the embedded SQL, and runs the full suite of 282 rules against them.

## Supported MyBatis Features
- **SQL Tags**: `<select>`, `<insert>`, `<update>`, `<delete>`, `<sql>`
- **Dynamic SQL Tags**: `<if>`, `<where>`, `<set>`, `<foreach>`, `<choose>`, `<when>`, `<otherwise>`, `<trim>`
- **Parameter Syntax**:
  - Safe: `#{param}` – uses prepared‑statement style parameterization.
  - Unsafe: `${param}` – direct string interpolation, flagged as potential SQL injection.
- **File Detection**: Files ending with `*Mapper.xml` or containing `mapper`/`mybatis` in the path are automatically treated as MyBatis mapper files.

## Usage Examples
### CLI
```bash
# Analyze a single mapper file
slowql src/main/resources/mapper/UserMapper.xml

# Analyze an entire mapper directory with schema validation
slowql src/main/resources/mapper/ --schema db/schema.sql
```
### API (Python)
```python
from slowql import SlowQL
engine = SlowQL()
results = engine.analyze_path('src/main/resources/mapper/')
print(results)
```
### CI/CD Integration
Add the following step to your CI workflow (GitHub Actions example):
```yaml
- name: SlowQL MyBatis analysis
  run: |
    pip install slowql
    slowql src/main/resources/mapper/ --format github-actions --fail-on high
```

## Security Considerations
- **`#{param}`** is considered safe because it is bound as a prepared‑statement parameter.
- **`${param}`** performs raw string interpolation and is flagged by SlowQL as a potential SQL injection (`SEC‑INJ‑001` … `SEC‑INJ‑011`).
- Dynamic tags (`<if>`, `<where>`, etc.) cause the query to be marked `is_dynamic = True`. SlowQL still analyzes the static parts and warns about patterns that could become vulnerable when combined with unsafe interpolation.

## Dynamic SQL Detection
When any of the dynamic tags are present, SlowQL marks the query as dynamic. This influences rule evaluation:
- Injection rules still apply to the static fragments.
- Performance rules such as `SELECT *` (`PERF‑SCAN‑001`) are evaluated on the final resolved query shape.
- Quality rules like hard‑coded table names (`QUAL‑DBT‑001`) are still reported.

## Common Issues Detected
| Rule | Description |
|------|-------------|
| `SEC‑INJ‑001` … `SEC‑INJ‑011` | Detects unsafe `${}` interpolation and dynamic SQL patterns that could lead to injection. |
| `PERF‑SCAN‑001` | Flags `SELECT *` usage, which can be costly in large tables. |
| `QUAL‑DBT‑001` | Flags hard‑coded table names that hinder portability. |

## Best Practices
- Prefer `#{param}` over `${param}` for all user‑supplied values.
- Keep dynamic SQL simple; avoid concatenating raw strings inside `<if>` blocks.
- Use explicit column lists instead of `SELECT *`.
- Validate mapper XML against a schema (e.g., MyBatis XSD) to catch structural errors early.

## Further Reading
- [MyBatis Official Documentation](https://mybatis.org/mybatis-3/)
- SlowQL rule reference: `SEC‑INJ‑001`, `PERF‑SCAN‑001`, `QUAL‑DBT‑001`
