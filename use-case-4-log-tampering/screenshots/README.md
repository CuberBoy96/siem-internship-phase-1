# Detection Use Case: Log Tampering Simulation (T1562.002)

## Scenario Description
The attacker attempts to clear security logs using `wevtutil` or other commands to hide malicious activity. This simulates real-world log tampering behavior after privilege escalation or lateral movement.

## Objective
Detect attempts to clear or remove Windows Event Logs using command-line utilities such as `wevtutil`, `clear-eventlog`, or `remove-eventlog`.

## Tools Used
- **SIEM**: Splunk Free
- **Log Source**: Sysmon (Event ID 1 - process creation)
- **Lab Setup**:
  - Windows 10 VM with Sysmon + Splunk Universal Forwarder
  - Splunk Web on host machine receiving forwarded logs

## Event ID / Data Source Mapping

| Source  | Event ID | Field       | Description                       |
|---------|----------|-------------|-----------------------------------|
| Sysmon  | 1        | CommandLine | Process creation (log tampering)  |

## Detection Logic / Query

```spl
index=* EventCode=1
| eval cmd=lower(CommandLine)
| where like(cmd, "%wevtutil%") OR like(cmd, "%clear-eventlog%") OR like(cmd, "%remove-eventlog%")
| table _time, host, ParentImage, Image, CommandLine, User
| sort -_time


