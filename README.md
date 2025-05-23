# SIEM Internship Phase-1
Phase 1

Welcome to the **SIEM Internship Phase-1** repository. This project is part of a hands-on cybersecurity internship focused on building a personal SOC (Security Operations Center) lab, simulating adversarial techniques, and detecting them using Splunk as the SIEM. Each use case is designed to introduce core concepts in log collection, parsing, threat detection, and alerting.

---

## 🎓 Internship Objective

* Set up a functional SIEM environment (Splunk Free edition)
* Collect logs from Windows machines via Universal Forwarder
* Simulate adversarial techniques
* Detect and alert on suspicious activity based on real-world attack patterns
* Document detection engineering tasks professionally

---

## 📚 Lab Architecture

* **Host Machine**: Running Splunk Web Interface
* **Windows 10 VM**: Target machine with Sysmon, Event Logs, Splunk Enterprise and Splunk Universal Forwarder
* **Kali Linux VM**: Used for attack simulation using tools like `hydra` and `crackmapexec`

Logs from the Windows VM are shipped to the host Splunk instance using Splunk Universal Forwarder.

---

## 📊 Use Cases Implemented

### 1. Brute Force Login Detection

* **Technique**: Multiple failed login attempts followed by successful login
* **Event IDs**: 4625 (Failure), 4624 (Success)
* **Tools**: crackmapexec (Kali), hydra (Kali), Windows Security Logs
* **Goal**: Detect brute force attempts followed by a successful privileged login from the same IP within 5 minutes

### 2. Suspicious Logon Times

* **Technique**: Privileged login outside business hours
* **Event ID**: 4624
* **Logic**: Detect admin logins beyond 7 PM or before 9 AM

### 3. Lateral Movement via RDP

* **Technique**: RDP logins using valid credentials after failed attempts
* **Event ID**: 4624 (LogonType=10), 4625
* **Goal**: Detect lateral movement attempts and correlate with previous failures

### 4. Log Tampering Simulation

* **Technique**: Clearing Windows Event Logs using commands like `wevtutil cl`
* **Event IDs**: Sysmon 1 (Process Execution), 1102 (Security log cleared)
* **Goal**: Detect attempts to tamper or clear log files

### 5. Hidden User Account Creation

* **Technique**: Adding a new user to the Administrators group
* **Event IDs**: 4720 (Account Created), 4732 (User added to group)
* **Goal**: Detect creation of suspicious accounts and privilege escalation

---

## 🗃️ Folder Structure

```
siem-internship-phase-1/
├── use-case-1-brute-force-login/
│   ├── screenshots/
│   ├── detection-logic/
│   └── writeups/
├── use-case-2-suspicious-logon-time/
├── use-case-3-lateral-movement-rdp/
├── use-case-4-log-tampering/
├── use-case-5-hidden-user-creation/
└── README.md
```

Each folder contains:

* `screenshots/`: Attack simulation, log entries, query results, and alerts
* `detection-logic/`: Detection queries used in Splunk (SPL)
* `writeups/`: Scenario explanation, objective, tools used, detection mapping

---

## 🌍 Tools Used

* **SIEM**: Splunk Free
* **Monitoring Tools**: Sysmon, Event Viewer
* **Attack Tools**: hydra, crackmapexec, PowerShell, net user, wevtutil
* **Forwarder**: Splunk Universal Forwarder for log shipping

---

## 📄 Submission Checklist

* [x] Screenshots of each detection scenario
* [x] SPL queries for alert logic
* [x] Markdown writeups per use case
* [x] Logs demonstrating detection in Splunk

---

## 🚀 Outcome

By completing this project, I learned:

* End-to-end log forwarding and detection engineering
* SPL query writing and alert creation in Splunk
* Threat simulation and mapping to MITRE ATT&CK
* GitHub documentation best practices

---

## 🌟 Special Thanks

To the mentors and community resources that helped along the way — and to the open-source community whose tools made this project possible.

---

Feel free to explore each use case folder to see queries, screenshots, and documentation of the detection logic.

---


