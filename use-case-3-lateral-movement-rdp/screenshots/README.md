# Detection Use Case: Lateral Movement via RDP (T1021.001)

## Scenario Description

An attacker simulates lateral movement by attempting multiple failed network logins using the `localuser` account, followed by a successful login from the same IP address. This is indicative of credential guessing or brute-force attempts that lead to a successful session over RDP or similar remote methods.

## Objective

Detect a pattern where an attacker tries to authenticate multiple times (failed logons), then successfully logs in using the same account within 5 minutes. This represents possible lateral movement using stolen or guessed credentials.

## Tools Used

* **SIEM**: Splunk Free
* **Log Source**: Windows Event Logs (Security)
* **Lab Setup**:

  * Single Windows 10 VM (Home Edition)
  * Simulated login attempts using `runas` and `net use` for `localuser`
  * Log forwarding via Splunk Universal Forwarder to Splunk Web (host machine)

## Event ID / Data Source Mapping

| Source       | Event ID / Field | Description                        |
| ------------ | ---------------- | ---------------------------------- |
| Windows Logs | 4625             | Failed login attempt (LogonType 3) |
| Windows Logs | 4624             | Successful login (LogonType 3)     |

## Detection Logic / Query

```spl
index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3
| eval status=if(EventCode=4625, "Failed", "Success")
| eval username=lower(coalesce(Account_Name, TargetUserName))
| eval is_failed=if(status="Failed", 1, 0)
| eval is_success=if(status="Success", 1, 0)
| stats
    max(eval(if(is_failed=1, _time, null()))) as last_failed_time,
    max(eval(if(is_success=1, _time, null()))) as success_time,
    count(eval(is_failed=1)) as failed_count,
    values(eval(if(is_failed=1, username, null()))) as failed_users,
    values(eval(if(is_success=1, username, null()))) as success_users
    by Source_Network_Address
| where failed_count >= 3
    AND isnotnull(success_time)
    AND (success_time - last_failed_time) <= 300
| eval last_failed_time=strftime(last_failed_time, "%Y-%m-%d %H:%M:%S"),
        success_time=strftime(success_time, "%Y-%m-%d %H:%M:%S"),
        time_gap=success_time." - ".last_failed_time
| table Source_Network_Address, failed_count, failed_users, success_users, last_failed_time, success_time, time_gap
| sort -failed_count
```

## Result

This query successfully detected failed login attempts followed by a successful login from the same IP address (`127.0.0.1` and local IPv6), confirming a simulated lateral movement attack using `localuser`.

## Screenshots

Stored in `/screenshots/` folder:

* `lateral_movement_detection.png` – shows failed + successful login correlation for `localuser`.
