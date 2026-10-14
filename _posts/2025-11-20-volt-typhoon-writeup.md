---
title: "Hands-On APT Investigation: Volt Typhoon | TryHackMe Writeup"
date: 2025-11-20 00:00:00 +0000
categories: [Writeups, TryHackMe]
tags: [Volt Typhoon, APT, Incident Response, Splunk, Windows Forensics]
description: "A comprehensive investigation into the Volt Typhoon APT simulation on TryHackMe, covering initial access, lateral movement, and stealth persistence techniques."
---

# Hands-On APT Investigation: Volt Typhoon | TryHackMe Writeup

## Overview
Notorious state-sponsored actor focused on targeting high-level organisations to enable potential disruption.

## Primary Targets
Telecom, energy, water, ports manufacturing, defence, government.

## Key Techniques
✅ Reconnaissance (Network Topology -T1590.004)  
✅ Resource Development (Acquire VPS Infrastructure -T1583.003)  
✅ Initial Access (Exploit Public-Facing Application-T1190)  
✅ Discovery (Local/Domain Account Discovery-T1087.001)  
✅ Defense Evasion (Obfuscated Files or Information -T1027.002)  
✅ Collection (Data from local system -T1005)  
✅ Exfiltration (Over C2-T1041)  
✅ Command and Control (Communication -T1071)

## Typical Workflow
Recon → Initial Access → Credential Theft → Lateral Movement → Persistence via C2

## Mitigation Measures
Implement strict credential management with MFA and regular audits, and monitor for LOTL activities. Secure network infrastructure by patching vulnerabilities and disabling unused services.

## Groups
Volt Typhoon is a People’s Republic of China (PRC) state-sponsored actor that has been active since at least 2021 primarily targeting critical infrastructure organizations in the US and its territories including Guam. Volt Typhoon’s targeting and pattern of behavior have been assessed as pre-positioning to enable lateral movement to operational technology (OT) assets for potential destructive or disruptive attacks. Volt Typhoon has emphasized stealth in operations using web shells, living-off-the-land (LOTL) binaries, hands on keyboard activities, and stolen credentials.

REF: https://attack.mitre.org/groups/G1017/

---

## Security Analyst Report

### 1. Executive Summary
This incident involves an advanced persistent threat (APT) simulated in the TryHackMe “Volt Typhoon” room. The attacker leverages living-off-the-land (LOTL) techniques, built-in Windows tools, and web shells to maintain stealth. The operation follows a full kill chain infrastructure compromise, credential theft, persistence, lateral movement, and cleanup that closely mirrors threat actor **Volt Typhoon (G1017)**, a Chinese state-sponsored group known for targeting critical infrastructure.

### 2. Threat Actor Profile
**Group:** Volt Typhoon (also known as BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236, etc.)  
**Motivation:** Espionage, pre-positioning for potential disruption of critical infrastructure.

**Techniques:**
- Living-off-the-land: Using built-in Windows tools (PowerShell, WMIC, ntdsutil, netsh) to evade detection.
- Web shells for persistence.
- Using proxy infrastructure for command & control.
- Cleaning up evidence by selectively clearing Windows event logs.

**Risk Profile:**  
Volt Typhoon poses a high risk to organizations that manage or belong to critical infrastructure (telecom, energy, communications). Their stealthy, persistent presence also raises the potential for not just espionage but future disruptive or destructive operations.

### 3. Analysis of the Incident
- **Initial Access:** The attacker exploited **ADSelfService Plus** (Zoho ManageEngine) to change Dean’s account password. They then created a new administrative account under Dean’s domain.
- **Execution:** Used **WMIC** to probe local drives on `server01` and `server02`. Employed `ntdsutil` to dump the Active Directory database (`NTDS.dit`) and later compressed it, setting a password on the archive.
- **Persistence:** Deployed a base64-encoded web shell `iisstart.aspx` into a specific directory on the web server.
- **Defense Evasion:** Used PowerShell to remove RDP. Renamed and changed the extension of the archive (the `.7z` file), helping to hide it. Checked registry paths to detect virtualized environments, likely to adapt behavior if running in a sandbox or VM.
- **Credential Access:** Queried the registry to identify software that might contain credentials; discovered three pieces of software the attacker was interested in. Found and decoded a PowerShell command to download and execute **Mimikatz**, which allowed the attacker to extract credentials from memory.
- **Discovery & Lateral Movement:** Used `wevtutil` to list specific event IDs, helping to enumerate Windows logs. Copied the web shell laterally from server01 to server02, under a new name, to maintain access across hosts.
- **Collection:** The attacker located and copied financial data files using PowerShell (Identified 3 such files in the search).
- **Command & Control (C2) & Cleanup:** Established a proxy for C2 using `netsh` to forward traffic. Identified the IP and port used. Cleared 4 types of event logs (Application, Security, Setup, System) to remove traces of the attack.

### 4. Recommendations
For an organization that might face this kind of threat:

- **Harden Externally-Facing Systems:** Patch and monitor systems like ADSelfService Plus or other self-service identity tools. Limit exposure of management interfaces to the internet.
- **Monitor for Living-Off-the-Land Behavior:** Deploy detections in SIEM/SOC for suspicious use of `ntdsutil`, `wevtutil`, and encoded PowerShell scripts. Set up behavioral baselines for command-line tools; anomaly detection can help.
- **Detect and Protect Web Shells:** Use file integrity monitoring on web server directories. Inspect for suspicious JSPX/ASPX files or base64-encoded payloads.
- **Credential Protection:** Implement memory protection (e.g., LSASS protection) and LAPS (Local Administrator Password Solution). Restrict access and auditing for credential-dumping tools like Mimikatz.
- **Log Management and Forensics:** Securely forward and back up Windows event logs to a remote, immutable system. Monitor for event log clearing commands or registry tampering.
- **Network Defense:** Segment networks to prevent lateral movement; isolate critical infrastructure and domain controllers. Inspect outbound traffic for unexpected proxying or tunneling (netsh-based C2).
- **Incident Response Preparedness:** Develop IR playbooks specific to APT behavior involving web shells, credential theft, and stealth persistence. Regularly run tabletop exercises simulating a Volt Typhoon-style intrusion.

---

## Task Walkthrough

Now that we know what we are dealing with let’s cover the challenge!

### Task 1: IR Scenario
**Volt Typhoon**  
**Scenario**: The SOC has detected suspicious activity indicative of an advanced persistent threat (APT) group known as Volt Typhoon, notorious for targeting high-value organizations. Assume the role of a security analyst and investigate the intrusion by retracing the attacker’s steps.

**Splunk Credentials**  
- **Username:** `volthunter`  
- **Password:** `voltyp1010`  
- **Splunk URL:** `http://MACHINE_IP:8000`

---

### Task 2: Initial Access
Volt Typhoon often gains initial access to target networks by exploiting vulnerabilities in enterprise software. In recent incidents, Volt Typhoon has been observed leveraging vulnerabilities in Zoho ManageEngine ADSelfService Plus.

> **Q1/ Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean’s password changed and their account taken over by the attacker?**

1. After logging in as **Admin** navigate to **Search & Reporting**.
2. Change the time range to **all time**.
3. Filter to minimize the number of logs and find the right answer:

**Splunk query:**  
`index="main" service_name=ADSelfServicePlus username="dean-admin" "Password Change"`  
*Or*  
`index=* sourcetype=adss username="dean-admin" status=completed action_name="Password Change"`

**Answer:** `2024-03-24T11:10:22`

> **Q2/ The attacker created a new administrative account shortly after gaining access. What is the name of this account?**

**Splunk query:**  
`index="main" sourcetype="WinEventLog" EventCode=4720`

**Answer:** `it-admin`

---

### Task 3: Execution
> **Q3/ The attacker used WMIC to probe local drives. What was the command line used?**

**Splunk query:**  
`index="main" sourcetype="WinEventLog" ProcessName="*wmic.exe" CommandLine="*logicaldisk*"`

**Answer:** `wmic logicaldisk get caption,description,filesystem,size,freespace`

---

### Task 4: Persistence
> **Q4/ A web shell was deployed for persistence. What is the name of the file?**

**Splunk query:**  
`index="main" sourcetype="WinEventLog" EventCode=11 TargetFilename="*aspx"`

**Answer:** `iisstart.aspx`

---

### Task 5: Defense Evasion
> **Q5/ The attacker cleared event logs to hide their tracks. How many types of event logs were cleared?**

**Splunk query:**  
`index="main" sourcetype="WinEventLog" EventCode=1102`

**Answer:** `4`

---

### Task 6: Credential Access
> **Q6/ The attacker dumped the NTDS.dit file. What tool was used?**

**Answer:** `ntdsutil`

---

### Task 7: Discovery
> **Q7/ The attacker queried the registry to find sensitive software. How many software pieces were they interested in?**

**Answer:** `3`

---

### Task 8: Lateral Movement
> **Q8/ The attacker moved the web shell to another server. What is the name of the second server?**

**Answer:** `server02`

---

### Task 9: Collection
> **Q9/ How many financial files were identified and copied by the attacker?**

**Answer:** `3`

---

### Task 10: Command & Control
> **Q10/ What is the IP and port used for the proxy established by the attacker?**

**Answer:** `192.168.1.134:8888`

---

## Conclusion
This writeup demonstrates the sophisticated techniques used by Volt Typhoon. By following the logs in Splunk, we were able to retrace every step of the attack from initial access to cleanup.

**References:**
- [MITRE ATT&CK: Volt Typhoon (G1017)](https://attack.mitre.org/groups/G1017/)
- [TryHackMe Room: Volt Typhoon](https://tryhackme.com/room/volttyphoon)
- [Splunk Cheat Sheet](https://www.stationx.net/splunk-cheat-sheet/)
