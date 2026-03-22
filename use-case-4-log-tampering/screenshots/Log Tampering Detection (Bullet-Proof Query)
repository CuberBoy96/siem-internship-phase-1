# 🔐 Windows Log Tampering Detection (Bullet-Proof Query)

This detection helps identify log clearing, audit policy tampering, and stealth logging bypass attacks (Ghost Attack).

---

## 🎯 What This Detects

- Log clearing (security/event logs wiped)
- Logging disabled ("Ghost Attack")
- Event log service shutdown
- Audit policy changes
- PowerShell log manipulation

---

## 👻 Ghost Attack Example

Attackers disable logging without clearing logs:

wevtutil sl Microsoft-Windows-Security-Auditing /e:false

Result:
- Logs remain visible
- New activity is NOT recorded
- Attacker operates silently

---

## 🧠 Detection Query

```spl
index=wineventlog (EventCode=4688 OR EventCode=1102 OR EventCode=104 OR EventCode=1100 OR EventCode=4719)
| eval cmd=lower(CommandLine)
| eval Activity=case(
    EventCode=1102 OR EventCode=104, "HARD_CLEAR: Log Wiped",
    EventCode=1100, "SERVICE_STOP: Event Log Service Shutdown",
    EventCode=4719, "POLICY_CHANGE: Audit Policy Disabled",
    match(cmd, "wevtutil.*(cl|sl|clear-log|set-log).*false"), "SUBVERSION: Disabling/Clearing via WevtUtil",
    match(cmd, "clear-eventlog|remove-eventlog"), "POWERSHELL: Log Manipulation",
    1=1, "Potential Tampering"
)
| table _time, host, User, Activity, CommandLine, ParentImage, Image
| sort - _time


---
