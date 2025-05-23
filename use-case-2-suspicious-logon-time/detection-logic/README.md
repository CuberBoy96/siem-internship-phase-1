# Detection Use Case: Suspicious Logon Times - After-Hours Admin Activity

## Scenario Description

An attacker or insider may attempt to access systems during unusual hours when monitoring is less active. This scenario simulates a privileged user (e.g., Administrator) logging in outside normal business hours (e.g., before 9:00 AM or after 7:00 PM). This type of activity is suspicious and may indicate lateral movement, persistence, or stealthy access.

## Objective

Detect successful logons by privileged accounts that occur outside defined business hours (09:00 to 19:00), which may suggest unauthorized or suspicious access.

## Tools Used

* **SIEM**: Splunk Free
* **Log Source**: Windows Event Logs (Security)
* **Lab Setup**:

  * Windows 10 VM (target) with Splunk Universal Forwarder
  * Splunk Web Interface on host machine for monitoring
  * Manual login simulation using built-in Administrator account

## Event ID / Data Source Mapping

| Source       | Event ID / Field | Description      |
| ------------ | ---------------- | ---------------- |
| Windows Logs | 4624             | Successful logon |

## Detection Logic / Query

```spl
index=* EventCode=4624
| eval fake_time=_time - 46800
| eval readable_time=strftime(fake_time, "%Y-%m-%d %H:%M:%S")
| eval hour=tonumber(strftime(fake_time, "%H"))
| eval is_admin=if(match(Account_Name, "Administrator|support1|admin"), 1, 0)
| where hour < 9 OR hour >= 19
| where is_admin=1
| table readable_time, Account_Name, Source_Network_Address, host, hour
```

## Result

This query successfully detected an after-hours logon using the Administrator account, returning 1 result. The time was artificially simulated by subtracting 13 hours from `_time` to test detection without needing to perform an actual midnight login.

## Screenshots

Relevant screenshots are stored in the `/screenshots/` folder:

* `after_hours_admin_logon.png` – query result showing simulated after-hours login by an admin *

  
