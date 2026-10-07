# Detection Engineering and Attack Chain Evaluation in an Active Directory SOC Environment

A security operations project: building a realistic SOC environment around an Active Directory domain, then using it to evaluate how well open-source detection tooling catches real adversary techniques — across two SIEMs, through full attack chains, under evasion, and end to end through incident response.

This is not a tutorial walkthrough. Every detection is treated as a tested hypothesis with positive **and** negative tests, resilience studies against controlled evasion, and documented limitations. The goal is an honest measurement of detection coverage and its gaps, not a collection of screenshots of alerts firing.

> EURECOM semester project, Fall 2026 — Security in Computer Systems and Communications. Supervisor: Aurélien Francillon.

---

## Objectives

1. Deploy a realistic SOC lab: Active Directory, endpoint telemetry, **two** SIEMs for comparison, and a case-management stack for incident response.
2. Engineer detections (Sigma) across multiple MITRE ATT&CK tactics, deployed and validated in both SIEMs.
3. Design and execute **multi-step attack scenarios** and evaluate per-step detection — what fired, what was missed, where the gaps are.
4. Test **detection resilience**: modify attacks to evade working rules, then improve the rules.
5. Take selected scenarios through a full **incident response** workflow, with IOC enrichment and SOC automation.
6. Produce a detection-coverage analysis (ATT&CK Navigator) and a **Wazuh vs. Splunk** comparative evaluation.

---

## Lab environment

| Component | Role | Status |
|---|---|---|
| Windows Server (Domain Controller) | Active Directory domain `aminesDomain`, DNS | built |
| Windows 10 | Domain-joined workstation (monitored endpoint) | built |
| Sysmon | Endpoint telemetry on Windows hosts | done |
| Splunk (Ubuntu) | SIEM #1 — log collection & detection | built |
| Kali Linux | Attack machine | built |
| Atomic Red Team | Attack simulation, mapped to ATT&CK | done |
| **Wazuh** | SIEM #2 — for comparative detection analysis | planned |
| **TheHive + Cortex** | Case management & IOC enrichment (incident response) | planned |
| **Suricata** *(200h extension)* | Network-level IDS for host+network correlation | stretch |

Full architecture and network diagram: [`/architecture`](./architecture).

---

## Methodology

Every detection ("analytic") is developed to a fixed definition of done:

1. **Detection hypothesis** — what behaviour is suspicious and why (a narrow, defensible claim)
2. **Data contract** — required log channels, event IDs, fields, audit/sensor config (verified before writing the rule)
3. **Executable rule** — Sigma, converted to both SIEMs
4. **Positive tests** — controlled attack variants
5. **Negative tests** — benign activity that exercises similar signals
6. **Results** — expected vs. actual, with evidence
7. **Limitations** — known misses and weak conditions
8. **Triage guidance** — what an analyst checks next

Attack outcomes are classified precisely — *prevented* / *executed & detected* / *executed & missed* / *telemetry absent* — because they mean very different things.

---

## Project phases

| Phase | Work | Status |
|---|---|---|
| **1. Lab infrastructure** | AD, Sysmon, Splunk, Kali, Atomic Red Team | done |
| | Wazuh (second SIEM), TheHive + Cortex | planned |
| **2. Detection engineering** | Sigma rules across ATT&CK tactics, deployed to both SIEMs | **active** |
| **3. Attack chains** | Multi-step scenarios, per-step detection evaluation | planned |
| **4. Resilience / evasion** | Bypass own rules, analyse, improve, regression-test | planned |
| **5. Incident response & automation** | Full cases in TheHive, IOC enrichment, Python automation, SOAR | planned |
| **6. Analysis & reporting** | ATT&CK Navigator coverage heatmap, Wazuh vs. Splunk comparison, report | planned |

The project is currently in **Phase 2**. Detection analytics are being built Splunk-first, then re-deployed and compared on Wazuh in Phase 6.

---

## Scope — detections

**8 detections + 2 correlations**, with **4 resilience studies** against the strongest detections.

| ID | Objective | ATT&CK | Tactic | Status |
|---|---|---|---|---|
| D01 | Suspicious LSASS access | T1003.001 | Credential Access | in progress |
| D02 | Suspicious PowerShell execution | T1059.001 | Execution | in progress |
| D03 | Suspicious service-ticket requests (Kerberoasting) | T1558.003 | Credential Access | planned |
| D04 | Suspicious remote service execution | T1021.002 / T1569.002 | Lateral Movement | in progress |
| D05 | Suspicious account privilege assignment | T1098 | Persistence | planned |
| D06 | Suspicious scheduled-task creation/modification | T1053.005 | Persistence / Execution | planned |
| D07 | NTDS.dit extraction via shadow copy | T1003.003 | Credential Access | planned |
| D08 | Security-monitoring / protection tampering | T1562.001 | Defense Evasion | planned |
| C01 | Account creation then privilege assignment | — | correlation | planned |
| C02 | Credential access then remote execution | — | correlation | planned |

**Resilience studies:** D01, D02, D03, D04.
**Stretch:** remote-thread injection (T1055); Pass-the-Hash *or* Pass-the-Ticket (T1550).

---

## Deliverables

- Working dual-SIEM SOC lab (AD, Sysmon, Splunk, Wazuh, TheHive, Cortex)
- Sigma detection rules with ATT&CK mapping and test results across both SIEMs
- Multi-step attack scenario analyses with per-step detection evaluation
- Resilience/evasion results with improved rules
- Incident response cases documented in TheHive
- Python automation scripts for SOC workflows
- ATT&CK detection-coverage heatmap (Wazuh vs. Splunk)
- Written project report

---

## Repository layout

```
analytics/           one folder per detection — each a full detection record
correlations/        multi-stage detections
resilience-studies/  evasion-and-improve experiments
attack-chains/       multi-step scenario analyses
incident-response/   TheHive case exports & investigation notes
architecture/        lab setup and diagram
scripts/             SOC automation (Python)
reports/             coverage heatmap, SIEM comparison, final report
```
