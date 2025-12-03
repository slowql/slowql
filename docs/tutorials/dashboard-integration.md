# Dashboard Integration Tutorial

This tutorial shows how to export SlowQL results and feed them into dashboards.

---

## 📤 Export JSON

```Bash
slowql --input-file sample.sql --export json --output results.json
```

---

## 🧱 Parse Results

Example Python script:

```code
import json
data = json.load(open("results.json"))
for finding in data["findings"]:
    print(f"{finding['severity']}: {finding['message']}")
```

---

## 📊 Feed Into Dashboard

- Import JSON into Grafana, Kibana, or custom dashboards  
- Use severity levels for filtering  
- Track trends over time  

---

## 🧠 Best Practices

- Export results in machine‑readable formats  
- Automate dashboard updates in CI/CD  
- Use visualizations to prioritize fixes  
