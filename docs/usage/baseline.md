# Baseline Mode

Baseline mode lets you adopt SlowQL on an existing codebase without fixing every pre-existing issue immediately. Only new issues introduced after the baseline is created are reported.

## Create a Baseline

``` bash
slowql src/ --update-baseline .slowql-baseline
``` 
This analyzes `src/`, saves all found issues as fingerprints, and exits with code 0.
Commit the baseline file to version control so all team members and CI pipelines share it.

## Use the Baseline

``` Bash
slowql src/ --baseline .slowql-baseline
```
Issues already in the baseline are suppressed. Only new issues are reported.
``` text
No issues found.
  (64 issues suppressed by baseline)
```

## Update the Baseline

After fixing some issues or deciding to accept new ones:
``` bash
slowql src/ --update-baseline .slowql-baseline
```

## How Fingerprinting Works

Issues are fingerprinted by content, not line number. Adding blank lines above an issue does not cause it to reappear in the next run. The fingerprint is based on the rule ID, message, and snippet content.

## CI/CD Integration

``` YAML
- name: Run SlowQL with Baseline
  run: slowql src/ --baseline .slowql-baseline --fail-on high
```
New developers introduce new code without seeing pre-existing warnings. Any new violation they introduce causes the build to fail.

## Custom Basline Path

``` Bash
slowql src/ --update-baseline path/to/baseline.json
slowql src/ --baseline path/to/baseline.json
```

