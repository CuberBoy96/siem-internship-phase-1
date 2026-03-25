# 🔍 Hidden User Detection Using Splunk

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Tool](https://img.shields.io/badge/Tool-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-User%20Monitoring-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

## 📌 Project Overview

This project demonstrates how to **detect hidden or suspicious user activity** using **Windows Security Logs** in **Splunk**.

It focuses on identifying:

* 👤 **User Account Creation**
* 👥 **User Added to Local Groups**
* 🛡️ **Privilege Escalation Attempts**
* 🔎 **Hidden User Behavior Detection**

---

## 🎯 Objectives

| 🎯 Goal                               | Description                                  |
| ------------------------------------- | -------------------------------------------- |
| 👤 Detect User Creation               | Identify when a new user account is created  |
| 👥 Detect Group Addition              | Monitor when users are added to groups       |
| 🛡️ Detect Admin Privilege Assignment  | Identify users added to Administrators group |
| 📊 Log Visualization                  | Display logs in structured table format      |

---

## 🧰 Technologies Used

| 🛠️ Tool                  | Purpose                  |
| --------------------------|--------------------------|
| 🪟 Windows OS            | Generate security events |
| 🔍 Splunk                | Log analysis & detection |
| 💻 Command Prompt        | User creation simulation |
| 📜 Windows Security Logs | Event data source        |

---

## 🧪 Lab Setup

| Component    | Value                 |
| ------------ | --------------------- |
| Machine Name | `DESKTOP-K7ML152`     |
| OS           | Windows               |
| Log Source   | Windows Security Logs |
| SIEM         | Splunk Enterprise     |

---

## ⚡ Attack Simulation

The following commands simulate suspicious activity.

### 👤 Create New User

```cmd
net user testuser2 p@ssw0rd /add
```

### 🛡️ Add User to Administrators Group

```cmd
net localgroup Administrators testuser2 /add
```

---

## 📜 Splunk Detection Query

```spl
index=* (EventCode=4720 OR EventCode=4732)
| eval event_desc=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Group")
| eval target_user=case(EventCode=4720, SAM_Account_Name, EventCode=4732, Member_Name)
| eval actor=Account_Name
| table _time, host, event_desc, target_user, actor, Group_Name, TaskCategory
| sort - _time
```

---

## 📊 Event Codes Reference

| Event ID | Icon | Description                  |
| -------- | ---- | ---------------------------- |
| **4720** | 👤   | User Account Created         |
| **4732** | 👥   | User Added to Security Group |

---

## 📷 Screenshots

### 🔍 Splunk Detection Query Output

<img src="images/splunk_query.png" width="800">

---

### 💻 User Creation via Command Prompt

<img src="images/user_creation.png" width="800">

---

## 📈 Expected Output

| Time      | Host            | Event           | User      | Group          |
| --------- | --------------- | --------------- | --------- | -------------- |
| Timestamp | DESKTOP-K7ML152 | Account Created | testuser2 | —              |
| Timestamp | DESKTOP-K7ML152 | Added to Group  | testuser2 | Administrators |

---

## 🚨 Detection Logic Explained

| Step | Description                                            |
| ---- | ------------------------------------------------------ |
| 1️⃣  | Monitor Event ID **4720** for new user creation        |
| 2️⃣  | Monitor Event ID **4732** for group membership changes |
| 3️⃣  | Extract usernames using `eval`                         |
| 4️⃣  | Display structured log table                           |
| 5️⃣  | Sort newest events first                               |

---

## 🧠 Why This Matters

Unauthorized account creation is a **common attacker persistence technique**.

This detection helps:

* 🚨 Identify **rogue users**
* 🛡️ Detect **privilege escalation**
* 🔍 Improve **incident response**
* 📊 Enhance **security monitoring**
  

```

## 🧪 Testing Steps

1️⃣ Create a new user

```cmd
net user testuser2 p@ssw0rd /add
```

2️⃣ Add user to admin group

```cmd
net localgroup Administrators testuser2 /add
```

3️⃣ Run Splunk query

4️⃣ Verify detection logs appear

---

## ✅ Results

✔ Successfully detected:

* 👤 User Creation
* 👥 Group Addition
* 🛡️ Admin Privilege Assignment

---

## 🔐 Security Use Cases

| Use Case                       | Description                      |
| ------------------------------ | -------------------------------- |
| Insider Threat Detection       | Monitor suspicious user activity |
| Privilege Escalation Detection | Identify admin access abuse      |
| Persistence Detection          | Detect attacker-created accounts |

---

## 🚀 Future Improvements

* 📊 Add Splunk Dashboard Visualization
* 🔔 Configure Real-Time Alerts
* 🧠 Integrate with MITRE ATT&CK Mapping
* ☁️ Forward logs to centralized SIEM

---

## 📚 MITRE ATT&CK Mapping

| Technique            | ID         |
| -------------------- | ---------- |
| Create Account       | **T1136**  |
| Account Manipulation | **T1098**  |
| Privilege Escalation | **TA0004** |

---

## 👨‍💻 Author

**Abhay**

Cybersecurity Enthusiast 🔐
SOC Analyst | Threat Detection | SIEM

---
