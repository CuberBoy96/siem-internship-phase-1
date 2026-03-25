# 🔍 Hidden User Detection Using Splunk

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Tool](https://img.shields.io/badge/Tool-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-User%20Monitoring-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# Detection Use Case: Log Tampering Simulation (T1562.002)

## Scenario Description
The attacker attempts to clear security logs using `wevtutil` or other commands to hide malicious activity. This simulates real-world log tampering behavior after privilege escalation or lateral movement.

## Objective
Detect attempts to clear or remove Windows Event Logs using command-line utilities such as `wevtutil`, `clear-eventlog`, or `remove-eventlog`.

## Tools Used
- **SIEM**: Splunk Free
- **Log Source**: Sysmon (Event ID 1102 - security log cleared), (Event ID 4688 - process creation), (Event ID 104 - log cleared) 
- **Lab Setup**:
  - Windows 10 VM with Sysmon + Splunk Universal Forwarder
  - Splunk Web on host machine receiving forwarded logs

## Event ID / Data Source Mapping

| Source  | Event ID | Field       | Description                          |
|---------|----------|-------------|--------------------------------------|
| Sysmon  | 104      | CommandLine | log cleared (log tampering)          |
| Sysmon  | 1102     | CommandLine | security log cleared (log tampering) |
| Sysmon  | 4688     | CommandLine | process creation (log tampering)     |

## Detection Logic / Query

## Basic Log Tampering Detection

This query detects common Windows log tampering techniques including:

- Security log clearing (EventCode 1102)
- System/Application log clearing (EventCode 104)
- Manual cleanup using wevtutil
- PowerShell log removal commands
- Resolves source IP to hostname using DNS lookup

```spl
index=* (EventCode=4688 OR EventCode=1102 OR EventCode=104)
| eval cmd=lower(CommandLine)
| eval Activity=case(
    EventCode=1102, "Security Log Cleared",
    EventCode=104, "System/App Log Cleared",
    match(cmd, "wevtutil.*(cl|clear-log)"), "Manual Cleanup (wevtutil)",
    match(cmd, "clear-eventlog|remove-eventlog"), "PowerShell Cleanup",
    1=1, "Other"
)
| where Activity!="Other"
| lookup dnslookup clientip AS src_ip OUTPUT clienthost AS src_host
| table _time, host, User, Activity, CommandLine, ParentImage, src_ip
| sort - _time







