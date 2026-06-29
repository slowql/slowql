# Java/Spring Integration

SlowQL analyzes MyBatis XML mapper files in Spring Boot projects and Java source files with embedded SQL strings.

## Project Structure

SlowQL scans any directory you point it at. For a typical Spring Boot project:
``` text
my-spring-app/
├─ src/main/resources/mapper/ # MyBatis XML mappers (analyzed)
├─ src/main/java/ # Java source (SQL strings extracted)
└─ pom.xml
```


## Scanning MyBatis Mappers

```bash
# Scan all mapper files
slowql src/main/resources/mapper/

# With schema validation
slowql src/main/resources/mapper/ --schema db/schema.sql

# Fail on high severity (for CI)
slowql src/main/resources/mapper/ --fail-on high
```

## Scanning Java Source
SlowQL extracts SQL from `prepareStatement()`, `createNativeQuery()` calls:

``` java
// Extracted and analyzed
String sql = "SELECT id, name FROM users WHERE active = true";
PreparedStatement stmt = conn.prepareStatement(sql);

// Extracted and flagged as dynamic
String query = "SELECT * FROM " + tableName + " WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
```

``` bash
slowql src/main/java/ --fail-on high
```

## GitHub Actions

``` YAML
name: SQL Analysis

on: [push, pull_request]

jobs:
  slowql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SlowQL
        run: |
          curl -L https://github.com/slowql/slowql/releases/latest/download/slowql-x86_64-linux \
            -o /usr/local/bin/slowql
          chmod +x /usr/local/bin/slowql

      - name: Analyze MyBatis Mappers
        run: slowql src/main/resources/mapper/ --fail-on high --format github-actions

      - name: Analyze Java Source
        run: slowql src/main/java/ --fail-on high --format github-actions
```

## Maven Integration
Run SlowQL as part of your Maven build using the exec plugin:
``` XML
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <version>3.1.0</version>
    <executions>
        <execution>
            <id>slowql-analysis</id>
            <phase>verify</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
                <executable>slowql</executable>
                <arguments>
                    <argument>src/main/resources/mapper/</argument>
                    <argument>--fail-on</argument>
                    <argument>high</argument>
                </arguments>
            </configuration>
        </execution>
    </executions>
</plugin>
```

## Gradle Integration
``` Groovy
task slowql(type: Exec) {
    commandLine 'slowql',
        'src/main/resources/mapper/',
        '--fail-on', 'high'
}

check.dependsOn slowql
```

## Pre-commit Hook
``` Bash
# .git/hooks/pre-commit
#!/bin/sh
slowql src/main/resources/mapper/ --fail-on high
if [ $? -ne 0 ]; then
  echo "SlowQL found SQL issues. Fix them before committing."
  exit 1
fi
```

``` Bash
chmod +x .git/hooks/pre-commit
```

## Common Issues in Spring Projects

| **Issue** | **Rule** | **Description** |
| --- | --- | --- |
| `${param}` in mapper | `SEC-INJ-001` | Use `#{param}` for prepared statement binding |
| `SELECT *` | `PERF-SCAN-001` | Specify column names explicitly |
| Missing `WHERE` in `DELETE` | `REL-DATA-001` | Unbounded `DELETE` will affect all rows |
| N+1 in loops | `REL-DATA-001` | Consider batch queries |