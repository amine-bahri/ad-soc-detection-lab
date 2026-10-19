# D01 — Suspicious LSASS Access (MITRE ATT&CK T1003.001)

**Technique:** OS Credential Dumping, LSASS Memory (T1003.001) · **Author:** Mohamed Amine BAHRI · **Status:** Splunk study complete; independent validation and Wazuh port pending · **Updated:** 2026-10-18

## Summary

LSASS holds the credentials of everyone logged on to a Windows machine, so reading its memory is one of the most important things a SOC has to catch. I took this one technique, ran it four different ways, and tested each against four detection angles. The result that matters: no single angle catches all four methods. Solid coverage comes from two complementary rules, one on the behaviour (a process opening lsass to read its memory) and one on the artifact (a dump file of lsass written to disk). The behavioural rule is built on what the four tested methods had in common, asking Windows for permission to read lsass memory. It does not claim to cover every possible credential-access path.

## Environment

| Item | Value |
|---|---|
| Monitored endpoint | Target-PC, Windows 10 22H2 (build 19045) |
| User context | `AMINE\Administrator`, elevated (an admin token holds SeDebugPrivilege, which is what permits opening lsass memory) |
| Domain | `amine.local` (NetBIOS AMINE), DC: ADDC01 |
| Sysmon | 15.22 binary, olafhartong balanced config (release 15.21, schemaversion 4.91) |
| Config SHA-256 | `64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E` (frozen for all four runs) |
| SIEM | Splunk, index `endpoint`, source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Defender | ON for the prevention test, OFF for controlled execution, restored ON afterward |

## What I tested

Four ways to dump lsass:
- **A1** comsvcs.dll MiniDump via rundll32 (a trusted Windows binary, writes a file)
- **A2** Sysinternals ProcDump `-ma` (a signed admin tool, writes a file)
- **A3** Task Manager, Create dump file (a GUI click, writes a file)
- **A4** Mimikatz `sekurlsa::logonpasswords` (reads memory in place, no file)

Four detection angles (Sysmon event IDs):
- **S1** command line (EID 1) · **S2** DLL load (EID 7) · **S3** dump file created (EID 11) · **S4** process access to lsass (EID 10)

## LSASS credential access: detection coverage across four methods

| Variant | S1 command line | S2 DLL load | S3 dump file | S4 process access |
|---|---|---|---|---|
| **A1 comsvcs** | HIT | HIT | HIT | HIT |
| **A2 procdump** | HIT | HIT | HIT | HIT |
| **A3 taskmgr** | N/A | HIT | HIT | not collected |
| **A4 mimikatz** | HIT (tool-specific strings) | MISS | N/A | HIT |

## What the matrix shows

- **S1 (command line)** is per-tool. The keywords that catch A1 and A2 do not match Mimikatz; A4 only appeared once I added Mimikatz-specific strings (sekurlsa). So A4 is catchable on the command line, but only if you already know the tool, which is brittle. A3 has no attacker command line (a GUI click), so S1 is N/A, not a miss.
- **S2 (DLL load)** depends on the tool loading the Windows dump engine. A1 and A2 load dbghelp and dbgcore; Mimikatz reads memory itself and never loads it, so S2 cannot see A4.
- **S3 (dump file)** catches anything that writes a dump to disk: A1, A2, A3. Mimikatz writes nothing, so S3 does not apply to it.
- **S4 (process access)** catches the act itself and hit A1, A2, A4. It misses A3 only because the Sysmon config excludes Task Manager as a source at the sensor, so no event is ever produced. You cannot query an event that was never collected, so A3 is covered by S3 instead.

Net: **across the four variants tested, S4 catches the in-memory one (Mimikatz) and S3 catches the file-writing ones, with A3 and A4 each sitting in the other's blind spot. The detection is the union of the two.**

The one thing S4 relies on: each of the four methods had to open lsass and ask to read its memory (the PROCESS_VM_READ right, which any direct memory read requires). The exact mask differed, full access (0x1FFFFF) for the file dumpers, a lean query-plus-read (0x1010) for Mimikatz, but the read bit was always set, which is what lets one behavioural rule catch tools it has not seen. Indirect paths that avoid a fresh read handle, such as duplicating an existing handle or dumping a process clone, would evade this signal; those belong to the evasion study.

## The rules

Two analytics. Files: `rule.yml` (S4), `rule-dumpfile.yml` (S3), `rule.spl` (both, as Splunk searches).

**S4, behavioural (primary).** A process opens lsass with a read-capable mask. The mask is an enumerated list (`0x1010`, `0x1410`, `0x1438`, `0x143A`, `0x1FFFFF`, `0x1F1FFF`, `0x1F3FFF`) that stands in for the real test, "does the mask include the read bit, `& 0x0010`." Sigma cannot express a bitwise AND, so the list approximates it; any value with that bit set belongs. Benign boot-time access by wininit, csrss and Sysmon is suppressed by full path, because those processes open lsass with the same full-access mask as the attacks.

**S3, artifact (complementary).** A dump file is written to disk by a known dump tool, or named like an lsass dump (Sysmon EID 11, which names the creating process in the `Image` field, not `SourceImage`). This covers A3, which S4 cannot see. Treat a hit as a lead, not proof the dump is of lsass: a benign `.dmp` written by one of these tools also matches. Corroborate with an S4 access event where one exists; for Task Manager there is no S4 event under the current collection (that is the whole reason this rule exists), so triage by file path, creating process and surrounding activity instead. The rule is named for what it observes, not what it concludes.

Severity: an S4 hit is **medium**, meaning a process gained the ability to read lsass (worth triage). As proposed analyst guidance, not an automated workflow implemented here, a hit is promoted to **high** when corroborated by a dump file, a dump-engine call stack (dbghelp/dbgcore/comsvcs), or an unusual source process. That keeps the common case low-noise without discarding it.

## Results

Over the attack day (2026-10-15), Defender off:

- **S4 untuned: 11 hits** (6 benign boot-time, 5 attack).
- **S4 tuned** (benign sources suppressed): **5 events, all from the attacks, 0 benign matches, nothing lost.**

Two honest caveats on those numbers. The 5 are events, not independent trials: there were four attack runs (A2 opens lsass several times, which is why it shows three events). And the 0 is a development result measured on the same dataset the tuning came from, so it is not yet an independent false-positive rate; the next test is a fresh reboot, logon and ordinary-use window.

The benign boot-time access is exactly why the mask alone is not enough: wininit opens lsass with `0x1FFFFF`, the same mask ProcDump and comsvcs use. Same mask, opposite intent. The rule handles this by suppressing trusted source processes, not by trusting the mask by itself.

## Why run with Defender off

The attacks ran with Defender off to isolate the detection layer from the prevention layer. On a default endpoint, Defender does block comsvcs and ProcDump against lsass, and I confirmed that in a prevention test. But a SOC cannot assume prevention is present or effective: the LSASS ASR rule is frequently unconfigured, attackers disable or add exclusions to AV, and signatures are tool-specific while behaviour is not. There is also a concrete trap, which I saw in the data: when Defender blocked the attack at launch, Sysmon recorded nothing, so the inspected SIEM window was empty. The only trace was in Defender's own operational log, which this lab did not forward. The lesson is to collect prevention telemetry separately, not to infer that nothing happened from missing Sysmon events. Detection is the layer that catches what prevention misses, and this rule keys on behaviour, not on any specific tool.

## Limitations

- **Mask approximation.** The enumerated list stands in for the bitwise read-bit test. A mask with the read bit set but not in the list would be missed. The list is extensible.
- **Suppression by source process.** Excluding wininit, csrss and Sysmon by path means an attacker who injects code into one of them, or masquerades as them in a non-system path, could slip the behavioural rule. The full-path match blocks the rename case. The injection case is a known gap, not yet closed: the tuned search removes those sources before it inspects anything, so it cannot re-catch them. Closing it needs a separate high-confidence search that looks at every lsass open with a dump-engine or unbacked-memory call stack, regardless of source. That is part of the evasion study.
- **The low false-positive surface is partly earned by the config's own tuning**, not only by a quiet environment. A log-everything ProcessAccess config produced 91 benign events in seconds in a control test. State the result as "near-zero under this tuned collection."
- **The S3 dump-file rule has coverage edges.** Removing the lsass filename hint only defeats the filename branch; a listed dump tool writing any `.dmp` still matches on the tool branch. What the rule genuinely misses is an event with neither the filename hint nor a listed creator, for example a renamed custom tool, or output that is not a `.dmp`.
- **Lab, not production.** One workstation, one domain, a known set of tools. Re-measure the baseline, including a boot cycle, before deploying anywhere real.
- **Next:** an evasion study that tests reflective (in-memory) Mimikatz, an open with a clean mask the rule does not list, and injection into a trusted source process, to find where these rules break.

## Evidence

All screenshots are in [`evidence/`](./evidence), detection-side Splunk captures only (the query plus SourceImage, GrantedAccess, CallTrace, command line, or file name). No Mimikatz output, hashes, or transcripts, by design.

![Untuned S4 over the attack day](./evidence/rule-untuned-11hits.png)
*Untuned S4 over 2026-10-15: 11 hits. The benign boot-time access (wininit, csrss, Sysmon64) sits at `0x1FFFFF`, the same mask the attacks use, which is exactly why the mask alone is not enough and trusted sources are suppressed.*

![Tuned S4 over the attack day](./evidence/rule-tuned-5hits.png)
*Tuned S4 on the development dataset: 5 attack-associated events (A1, A2, A4), no remaining benign matches. Independent benign validation is pending.*

Full per-variant captures backing each cell of the matrix are in `evidence/`, named `A<n>-S<n>-*.png` (for example `A2-S3-dumpfile.png`, `A3-S4-empty.png`), plus `sensor-probe.png` for the baseline sensor check.

## Triage (when the rule fires)

Proposed analyst steps, in order:
1. **SourceImage:** a signed tool in a normal path, or something unusual (unsigned, user-writable path, odd name)?
2. **GrantedAccess and CallTrace:** does the stack pass through the dump engine (dbghelp/dbgcore/comsvcs) or show unbacked (UNKNOWN) frames? Either raises confidence.
3. **Parent process and command line (EID 1):** how was it launched, and by what?
4. **Dump file (EID 11):** did a `.dmp` appear around the same time on the same host and process?
5. **User and host:** an Administrator-to-SYSTEM crossing, or a hit on a domain controller, raises severity.

## Credential hygiene

Mimikatz succeeded for a disposable lab account. Per lab policy, the recovered credential material was not screenshotted, saved, or committed. This repository contains only sanitized proof statements, the detection logic, and detection-side screenshots. The Mimikatz binary, any `.dmp` files, and the credential-bearing PowerShell transcript are excluded (`.gitignore` blocks them).

## Credits

Sysmon configuration: olafhartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular), balanced profile, used under its own license and frozen by hash for this study.
