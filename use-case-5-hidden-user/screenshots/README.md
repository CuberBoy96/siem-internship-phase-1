Detection Use Case: Hidden User Creation (T1136)
Scenario Description

The attacker creates a new local user account and adds it to a privileged group such as Administrators. This simulates real-world persistence techniques where attackers create hidden or unauthorized users to maintain access.

Objective

Detect unauthorized user account creation and group membership changes using Windows Security Event Logs.

Tools Used
SIEM: Splunk Free
Log Source: Windows Security Logs
Lab Setup:
Windows 10 VM with Splunk Universal Forwarder
Splunk Web on host machine receiving forwarded logs
Attack Simulation Commands

The attacker creates a new user and adds it to the Administrators group.

net user testuser2 p@ssw0rd /add
net localgroup Administrators testuser2 /add
Event ID / Data Source Mapping
Source	Event ID	Field	Description
Security	4720	SAM_Account_Name	User account created
Security	4732	Member_Name	User added to group
Detection Logic / Query
Hidden User Creation Detection

This query detects suspicious user account creation and group additions including:

New user account creation (EventCode 4720)
Users added to groups (EventCode 4732)
Privilege escalation through group membership
index=* (EventCode=4720 OR EventCode=4732)
| eval event_desc=case(
    EventCode=4720, "Account Created",
    EventCode=4732, "Added to Group"
)
| eval target_user=case(
    EventCode=4720, SAM_Account_Name,
    EventCode=4732, Member_Name
)
| eval actor=Account_Name
| table _time, host, event_desc, target_user, actor, Group_Name, TaskCategory
| sort - _time
Expected Outcome

After running the attack commands:

A new user account is created
The user is added to a privileged group
Windows generates Security Event IDs 4720 and 4732
Splunk detects and logs the suspicious activity
MITRE ATT&CK Mapping
Technique	ID	Description
Create Account	T1136	Local account creation
Account Manipulation	T1098	Adding users to privileged groups
