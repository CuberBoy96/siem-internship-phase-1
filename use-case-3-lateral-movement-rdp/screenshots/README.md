# 🔍 Lateral Movement Detection Using Splunk

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Tool](https://img.shields.io/badge/Tool-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-User%20Monitoring-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

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
index=* (EventCode=4625 OR EventCode=4624) Logon_Type IN (3,10)
| eval status=case(EventCode=4625, "Failed", EventCode=4624, "Success")
| eval user=coalesce(Account_Name, TargetUserName)
| eval src_ip=coalesce(Source_Network_Address, IpAddress)

| where isnotnull(src_ip) AND src_ip!="-"
| sort 0 src_ip _time

| streamstats current=f last(eval(if(status="Failed", _time, null()))) as last_failed_time by src_ip
| streamstats count(eval(status="Failed")) as failed_count by src_ip

| where status="Success"
    AND failed_count >= 3
    AND isnotnull(last_failed_time)
    AND _time > last_failed_time
    AND (_time - last_failed_time) <= 300

| eval success_time=_time
| eval time_diff_sec = success_time - last_failed_time

| eventstats dc(user) as distinct_users by src_ip

| stats 
    latest(failed_count) as failed_count,
    values(username) as users,
    values(distinct_users) as distinct_users,
    min(last_failed_time) as first_failed_time,
    max(success_time) as success_time
    by src_ip

| eval attack_type=case(
    distinct_users>=5, "Password Spraying",
    failed_count>=5, "Brute Force",
    true(), "Other"
)

| eval severity=case(
    failed_count>=10, "High",
    failed_count>=5, "Medium",
    true(), "Low"
)

| eval first_failed_time=strftime(first_failed_time,"%Y-%m-%d %H:%M:%S"),
       success_time=strftime(success_time,"%Y-%m-%d %H:%M:%S")

| sort -failed_count
```

## Result

This query successfully detected failed login attempts followed by a successful login from the same IP address (`127.0.0.1` and local IPv6), confirming a simulated lateral movement attack using `localuser`.

## Screenshots

Stored in `/screenshots/` folder:

* `lateral_movement_detection.png` – shows failed + successful login correlation for `localuser`. *

  

  
