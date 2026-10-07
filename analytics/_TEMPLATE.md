# D0X — <detection objective>

**ATT&CK:** T____ (<technique name>)
**Status:** ⬜ planned / 🔜 in progress / ✅ complete
**Last updated:** YYYY-MM-DD

---

## 1. Detection hypothesis
*What behaviour is suspicious, and why. State a narrow, defensible claim — e.g. "suspicious access to LSASS memory," not "credential dumping detection."*



## 2. Data contract
*What this detection needs in order to work — verified to exist before writing the rule.*

| Requirement | Detail | Verified? |
|---|---|---|
| Log channel | e.g. Sysmon Operational | ⬜ |
| Event ID(s) | e.g. EID 10 | ⬜ |
| Key fields | e.g. SourceImage, GrantedAccess, CallTrace | ⬜ |
| Audit policy / sensor config | e.g. Sysmon ProcessAccess rule for lsass.exe | ⬜ |

## 3. Executable rule

**Sigma:**
```yaml
# rule.yml
```

**Splunk (SPL):**
```
# rule.spl
```

**Conversion notes:** *anything that didn't translate cleanly between Sigma and SPL/Wazuh.*

## 4. Positive tests
*At least two controlled variants where feasible.*

| # | Test | Tool / command | Expected |
|---|---|---|---|
| P1 | | | |
| P2 | | | |

## 5. Negative tests
*Benign activity that exercises similar signals — to find false positives.*

| # | Benign activity | Why it might trip the rule |
|---|---|---|
| N1 | | |

## 6. Results

| Test | Outcome | Evidence | Notes |
|---|---|---|---|
| P1 | prevented / executed&detected / executed&missed / telemetry-absent | | |
| P2 | | | |
| N1 | (false positive? yes/no) | | |

**Measurements:** detections out of attempts; false positives out of benign tests; detection latency (ingest vs. search); query runtime.

## 7. Limitations
*Known misses, dependencies, conditions where the conclusion is weak. Be honest — a documented blind spot beats a false claim of full coverage.*



## 8. Triage guidance
*When this alert fires, what should an analyst look at next?*


