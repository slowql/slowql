# Java/Spring Integration

## Scanning MyBatis Mappers in Spring Boot Projects
SlowQL can automatically discover MyBatis mapper XML files in typical Spring Boot project structures. By default, it looks for files matching `*Mapper.xml` under `src/main/resources/mapper/` or any directory containing `mapper` or `mybatis` in its path.

## Project Structure Example
```
my-spring-app/
├─ src/
│  ├─ main/
│  │  ├─ java/com/example/app/   # Java source code
│  │  └─ resources/
│  │     └─ mapper/               # MyBatis XML mappers
│  │        ├─ UserMapper.xml
│  │        └─ OrderMapper.xml
│  └─ test/
└─ pom.xml (or build.gradle)
```

## Maven/Gradle Integration
Add SlowQL as a development dependency and run it as part of your build.

### Maven
```xml
<dependency>
    <groupId>com.github.makroumi</groupId>
    <artifactId>slowql</artifactId>
    <version>1.6.2</version>
    <scope>test</scope>
</dependency>
```
Create a Maven plugin execution (using the `exec-maven-plugin`) to run SlowQL:
```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <version>3.1.0</version>
    <executions>
        <execution>
            <id>slowql-analysis</id>
            <phase>verify</phase>
            <goals><goal>java</goal></goals>
            <configuration>
                <mainClass>slowql.cli.Main</mainClass>
                <arguments>
                    <argument>src/main/resources/mapper/</argument>
                    <argument>--format</argument>
                    <argument>github-actions</argument>
                </arguments>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### Gradle
```groovy
dependencies {
    testImplementation "com.github.makroumi:slowql:1.6.2"
}

task slowql(type: JavaExec) {
    classpath = sourceSets.test.runtimeClasspath
    main = "slowql.cli.Main"
    args = ["src/main/resources/mapper/", "--format", "github-actions"]
}

check.dependsOn slowql
```

## Pre‑commit Hook for Java Projects
Add a Git hook to run SlowQL before each commit:
```bash
# .git/hooks/pre-commit
#!/bin/sh
pip install slowql
slowql src/main/resources/mapper/ --fail-on high
if [ $? -ne 0 ]; then
  echo "SlowQL detected issues in MyBatis mappers. Commit aborted."
  exit 1
fi
```
Make the script executable: `chmod +x .git/hooks/pre-commit`.

## CI/CD Examples
### GitHub Actions
```yaml
name: SlowQL MyBatis Analysis
on: [push, pull_request]
jobs:
  mybatis-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install SlowQL
        run: pip install slowql
      - name: Run SlowQL on MyBatis mappers
        run: |
          slowql src/main/resources/mapper/ --format github-actions --fail-on high
```
### Jenkins (Declarative Pipeline)
```groovy
pipeline {
    agent any
    stages {
        stage('Static Analysis') {
            steps {
                sh 'pip install slowql'
                sh 'slowql src/main/resources/mapper/ --format github-actions --fail-on high'
            }
        }
    }
}
```
### GitLab CI
```yaml
slowql_mybatis:
  image: python:3.11-slim
  script:
    - pip install slowql
    - slowql src/main/resources/mapper/ --format gitlab-ci --fail-on high
  only:
    - merge_requests
    - branches
```

These integrations ensure that any new or modified MyBatis mapper files are automatically scanned for security, performance, and quality issues before they are merged or deployed.
