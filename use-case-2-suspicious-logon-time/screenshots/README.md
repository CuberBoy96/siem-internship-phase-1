# Detection Use Case: Suspicious Logon Time – After-Hours Admin Activity (T1078.004)

## Scenario Description
This scenario simulates a privileged account logging in outside regular business hours, which could indicate unauthorized access. For example, an admin logs in at 2:30 AM and accesses key folders or services.

## Objective
Detect logins by privileged accounts occurring **outside defined business hours** (e.g., before 9 AM or after 7 PM). This can help identify abnormal behavior or compromised accounts.

## Tools Used
- **SIEM**: Splunk Free
- **Log Source**: Windows Event Logs (Security)
- **Lab Setup**:
  - Windows 10 VM with Splunk Universal Forwarder
  - Host machine running Splunk Web Interface
  - Admin account logs in outside business hours

## Event ID / Data Source Mapping

| Source        | Event ID | Field         | Description                        |
|---------------|----------|---------------|------------------------------------|
| Windows Logs  | 4624     | Logon events  | Indicates successful logon         |

## Detection Logic / Query

```spl
index=* EventCode=4624
| eval fake_time=_time - 46800
| eval readable_time=strftime(fake_time, "%Y-%m-%d %H:%M:%S")
| eval hour=tonumber(strftime(fake_time, "%H"))
| eval username_clean=lower(replace(Account_Name, ".*\\", ""))
| eval is_admin=if(match(username_clean, "Administrator|abhay|admin"), 1, 0)
| where hour < 9 OR hour >= 19
| where is_admin=1
| table readable_time, username_clean, Account_Name, Source_Network_Address, host, hour
