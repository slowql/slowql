# Jenkins

This example shows how to run SlowQL inside a Jenkins pipeline to automatically analyze SQL files during builds.

---

## 📂 Pipeline Configuration

Add a stage to your `Jenkinsfile`:

```code
pipeline {
  agent any
  stages {
    stage('SlowQL Analysis') {
      steps {
        sh '''
          python3 -m venv .venv
          . .venv/bin/activate
          pip install slowql
          slowql --no-intro --fast --input-file sample.sql --export json --output results.json
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'results.json', fingerprint: true
        }
      }
    }
  }
}
```

---

## 📦 Sample SQL File

Include a file like `sample.sql` in your repo:

```code
SELECT * FROM users WHERE email LIKE '%@gmail.com';  
DELETE FROM orders;
```

---

## 📤 Exported Results

The pipeline will generate `results.json` containing all detector findings. Jenkins will archive it as a build artifact for inspection.

---

## 🧠 Best Practices

- Use `--no-intro` for clean logs  
- Use `--fast` for quicker builds  
- Export to JSON for machine‑readable results  
- Archive artifacts for compliance and debugging  

---

## 🔗 Related Examples

- [Basic Usage](basic-usage.md)  
- [GitHub Actions](github-actions.md)  
- [GitLab CI](gitlab-ci.md)  
- [Pre-Commit Hook](pre-commit-hook.md)  
