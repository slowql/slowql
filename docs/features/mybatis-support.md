# MyBatis XML Support

SlowQL parses MyBatis XML mapper files and analyzes the embedded SQL with the full rule set.

## Detection

Files are analyzed as MyBatis mappers when they contain a `<mapper>` root element. The `.xml` extension triggers the MyBatis parser path.

## Supported Tags

| Tag Type | Tags |
|----------|------|
| Statement | `<select>`, `<insert>`, `<update>`, `<delete>`, `<sql>` |
| Dynamic | `<if>`, `<where>`, `<set>`, `<foreach>`, `<choose>`, `<when>`, `<otherwise>`, `<trim>` |

## Parameter Syntax

| Syntax | Safety | Rule |
|--------|--------|------|
| `#{param}` | Safe - prepared statement | No issue |
| `${param}` | Unsafe - string interpolation | `SEC-INJ-001` |

## Dynamic SQL Detection

Queries containing dynamic tags are marked `is_dynamic = true`. Dynamic queries are demoted from `proven` to `contextual` confidence since the final SQL shape depends on runtime values.

## Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.example.UserMapper">

  <!-- Safe parameterization -->
  <select id="findById" resultType="User">
    SELECT id, name FROM users WHERE id = #{id}
  </select>

  <!-- Flagged: unsafe interpolation -->
  <select id="search" resultType="User">
    SELECT * FROM users WHERE name LIKE ${searchTerm}
  </select>

  <!-- Dynamic SQL - analyzed with contextual confidence -->
  <update id="updateUser">
    UPDATE users
    <set>
      <if test="name != null">name = #{name},</if>
      <if test="email != null">email = #{email}</if>
    </set>
    WHERE id = #{id}
  </update>

</mapper>
```

Rules fired on this file:
- `SEC-INJ-001` on `${searchTerm}` (critical, unsafe interpolation)
- `PERF-SCAN-001` on `SELECT *` (medium, select star)

## Usage
``` Bash
# Analyze a mapper file
slowql UserMapper.xml

# Analyze a directory of mappers
slowql src/main/resources/mapper/

# With schema validation
slowql src/main/resources/mapper/ --schema db/schema.sql
```

## MyBatis SQL Fragment Inclusion
SlowQL detects `<include refid="...">` references and attempts to resolve them when the referenced `<sql>` fragment is in the same file.

## Suppression
``` XML
<!-- slowql-disable-line PERF-SCAN-001 -->
<select id="getAll" resultType="User">
  SELECT * FROM users
</select>
```