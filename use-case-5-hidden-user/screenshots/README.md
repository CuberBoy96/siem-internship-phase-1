👤 Hidden User Creation Detection (Splunk)

This project demonstrates how attackers create unauthorized users and add them to privileged groups, and how to detect this activity using Splunk.

Attackers often create hidden users to maintain persistence and gain administrative privileges.

🎯 What This Detects
👤 New user account creation
➕ Users added to privileged groups
🔐 Privilege escalation attempts
🕵️ Hidden or unauthorized admin users
🧪 Attack Simulation — Hidden User Creation

Attackers create a new user and add it to the Administrators group.

Step 1 — Create a New User
net user testuser2 p@ssw0rd /add
Step 2 — Add User to Administrators Group
net localgroup Administrators testuser2 /add
Result
A new user account is created
The user is added to the Administrators group
Administrative privileges are granted
📊 Events Generated

These commands generate important Windows Security Events:

Event ID	Description
4720	User account created
4732	User added to group

These events are critical for detecting unauthorized account creation.

🧠 Detection Query (Splunk)

This Splunk query detects new user creation and group additions.

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


🧰 Tools Used
Windows 10
Splunk Enterprise
Command Prompt
Windows Event Viewer

-------------

🚀 Skills Demonstrated
Windows Security Monitoring
Splunk Query Writing (SPL)
User Activity Monitoring
Threat Detection
Blue Team Fundamentals
📚 MITRE ATT&CK Mapping
Technique	ID	Description
Create Account	T1136	Creating new local user accounts
Account Manipulation	T1098	Adding users to privileged groups
🛡️ Why This Matters

Attackers commonly create hidden users to:

Maintain persistence
Gain administrative access
Return later without detection

Detecting unauthorized account creation is a critical blue-team skill.
