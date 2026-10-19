# Lab Architecture

## Network

- **Domain:** `amine.local` (NetBIOS `AMINE`)
- **Network:** `192.168.10.0/24` (VirtualBox NAT Network). Isolated from other hosts on the physical network; outbound internet is available through NAT, so this is a contained lab, not air-gapped.

| Host | IP | Role |
|---|---|---|
| Splunk Server (Ubuntu) | 192.168.10.10 | SIEM / log collection |
| Domain Controller (Windows Server) | 192.168.10.7 | Active Directory, DNS |
| Windows 10 (`Target-PC`) | DHCP | Domain-joined workstation |
| Kali Linux | 192.168.10.250 | Attack machine |

## Telemetry pipeline

```
Windows endpoints (DC + Target-PC)
  ├── Sysmon                -> detailed endpoint events (process, network, process access, image load, file create)
  └── Windows Event Logs    -> Security, System, PowerShell operational
        │
        └── Splunk Universal Forwarder -> Splunk indexer (192.168.10.10) -> search and detections
```

## Telemetry sources collected

| Source | Purpose | Status |
|---|---|---|
| Sysmon Operational | Process creation, process access, image load, file create, network, named pipes | collected |
| Windows Security | Logons, account changes, Kerberos | workstation logons collected; DC audit policy (4769, 4728/4732) to verify |
| PowerShell Operational (script-block, EID 4104) | PowerShell content logging | to enable |

## Diagram

![Lab network diagram](./Diagram1.png)

## Notes and lessons

- The lab network blocks outbound DNS to public resolvers (8.8.8.8); endpoints use the local network resolver instead.
- No VM snapshots are configured yet, so baseline state is re-established manually. Adding per-VM snapshots is a planned improvement: their absence made recovery slower after a disk-space incident during the D01 phase.
- Sysmon runs the olafhartong balanced config, frozen (hash recorded) for the duration of each detection study so results are reproducible.
