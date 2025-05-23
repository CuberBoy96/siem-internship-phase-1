# Detection Use Case: Brute Force Login Detection

## Scenario Description

A brute-force attack was simulated from a Kali Linux VM targeting a Windows 10 VM. Multiple failed login attempts (Event ID 4625) were triggered using `crackmapexec`, followed by a successful login using a privileged account. The goal is to detect a sequence of failed logins followed by a successful login from the same source IP within a short time frame.

## Objective

Detect when a brute-force login attempt is followed by a successful login using a privileged account (e.g., administrator) within 5 minutes, to identify potential account compromise.

## Tools Used

* **SIEM**: Splunk Free
* **Log Source**: Windows Event Logs (Security), Sysmon
* **Lab Setup**:

  * Windows 10 VM (target) with Splunk Universal Forwarder
  * Kali Linux VM (attacker) with crackmapexec
  * Host machine running Splunk Web Interface for monitoring

## Event ID / Data Source Mapping

| Source       | Event ID / Field | Description                |
| ------------ | ---------------- | -------------------------- |
| Windows Logs | 4625             | Failed login attempt       |
| Windows Logs | 4624             | Successful login           |
| Sysmon       | Event ID 1       | (Used in other detections) |

## Detection Logic / Query

```spl
index=* (EventCode=4625 OR EventCode=4624)
| eval
    status=if(EventCode=4625, "Failed", "Success"),
    username=lower(coalesce(Account_Name, User)),
    is_admin=if(match(username, "admin|administrator|root|svc"), 1, 0)
| eval
    is_failed_non_admin=if(status="Failed" AND is_admin=0, 1, 0),
    is_admin_success=if(status="Success" AND is_admin=1, 1, 0)
| stats
    max(eval(if(is_failed_non_admin=1, _time, null()))) as last_failed_time
    max(eval(if(is_admin_success=1, _time, null()))) as admin_success_time
    count(eval(is_failed_non_admin=1)) as failed_count
    values(eval(if(is_failed_non_admin=1, username, null()))) as failed_usernames
    values(eval(if(is_admin_success=1, username, null()))) as admin_accounts
    by Source_Network_Address
| where
    failed_count >=10
    AND isnotnull(admin_success_time)
    AND (admin_success_time - last_failed_time) <= 300
| eval
    time_window=admin_success_time - last_failed_time,
    last_failed_time=strftime(last_failed_time, "%Y-%m-%d %H:%M:%S"),
    admin_success_time=strftime(admin_success_time, "%Y-%m-%d %H:%M:%S")
| table
    Source_Network_Address
    failed_count
    failed_usernames
    admin_accounts
    last_failed_time
    admin_success_time
    time_window
| sort -failed_count
```

## Result

This query successfully detects brute-force attempts from the same IP followed by privileged login, returning 1 result during test execution. An alert was created in Splunk based on this query to notify when this pattern is detected.

## Screenshots

Relevant screenshots are stored in the `/screenshots/` folder:

* `attack_simulation_kali.png` – shows crackmapexec brute-force command
* `event_logs_windows.png` – shows Event ID 4625/4624 entries in Windows
* `splunk_query_result.png` – shows query output in Splunk
* `splunk_alert_config.png` – shows configured alert in Splunk

