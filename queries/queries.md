## Claude and Splunk Queries

---

## CLAUDE PROMPTS

### 1.1 Reconnaissance & Scanning

```
"Query the tpot index and identify the top 10 IPs performing port scanning 
activity. For each IP, show which ports they scanned and which honeypots they 
triggered, ordered by total event count."
```
```
"Find all Suricata events with signature 2009582 (NMAP -sS scan). For each 
source IP, show their scan timing pattern — are they scanning continuously or 
in bursts?"
```
```
"Look at Honeytrap events and identify IPs that scanned more than 50 unique 
destination ports. These are likely performing comprehensive host discovery."
```


### 1.2 Credential & Brute-Force Analysis

```
"From Cowrie logs, extract all failed login attempts. What are the top 20 
username:password combinations attempted? Are any of these known default 
credentials for IoT devices like routers or cameras?"
```
```
"Identify IPs in the Cowrie logs that attempted more than 100 login attempts 
in under 60 seconds. Show their username and password patterns — are they 
using dictionaries or single-password spray techniques?"
```
```
"From Cowrie, find all successful logins (eventid cowrie.login.success). For 
each, trace the full session — what commands did the attacker run after 
gaining access?"
```

### 1.3 Exploitation & Payload Analysis

```
"Search the Dionaea logs for HTTP request bodies containing 'shell_exec' or 
'base64_decode'. Show me the decoded payloads where possible, and which IPs 
are sending them."
```
```
"Find all Suricata alerts for CVE-2024-4577 and CVE-2017-9841 (PHP 
exploitation). Correlate these with Dionaea HTTP logs from the same source IPs 
to see if exploitation attempts were successful."
```
```
"What is the full timeline of activity for IP 201.216.239.205? Show me every 
event across all honeypots in chronological order, including what service they 
hit, what credentials or commands they used, and any files they downloaded."
```

### 1.4 Post-Exploitation & Malware

```
"From Cowrie session file_download events, list all unique file hashes 
downloaded by attackers. Group IPs by which files they downloaded — are 
multiple IPs downloading the same payload? This suggests a coordinated campaign."
```
```
"In AdbHoney logs, find all instances of commands that include 'wget', 'curl', 
or 'chmod'. Extract the URLs being fetched and show me which IPs are fetching them."
```
```
"Are there any IPs that triggered both Cowrie (SSH brute-force) AND 
Suricata EternalBlue alerts (SID 2024766)? These dual-vector attackers may 
represent more sophisticated operators."
```

### 1.5 Infrastructure & Campaign Correlation

```
"Group all attacking IPs by their ASN. Which cloud providers are hosting the 
most attack infrastructure? Show me the top 5 ASNs and a representative sample 
of IPs from each."
```
```
"Are there IPs from the Attacker Source IP Top 10 list that appear across 
multiple honeypots? A single IP hitting SSH, SMB, and HTTP suggests an 
automated multi-vector scanner."
```
```
"Look at the attack timeline. Was the spike in January–April 2026 driven by 
a specific attack type or honeypot? Did new CVEs or new IPs appear during 
this period, or was it existing actors scaling up?"
```

### 1.6 IOC Generation

```
"Generate a list of all unique source IPs that triggered at least 3 different 
Suricata alert signatures. Format the output as a CSV with columns: IP, ASN, 
Country, Total Events, Alert Types."
```
```
"Extract all unique file hashes from Cowrie downloads and Dionaea captures. 
Format as a list suitable for VirusTotal bulk lookup."
```
```
"Find all URLs or domains that appeared in Cowrie wget/curl commands or 
Dionaea HTTP referrer headers. These are potential C2 or dropper infrastructure."
```

---

## 2\. SPLUNK QUERIES

### All Sourcetypes and Event Counts
```spl
index=honeypot | stats count by sourcetype | sort -count
```

### Top 20 attacking IPs
```spl
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats count by src_ip | sort -count | head 20
```


### Total Unique IPs and Events (Application Layer)

```spl
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats dc(src_ip) as unique_ips, count as total_events
```

### Total Unique IPs and Events (Suricata, External Only)

```spl
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats dc(src_ip) as unique_ips, count as total_events
```

### Geographic Distribution (Top 15 Countries)

```spl
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json
| iplocation src_ip
| stats count by Country
| sort -count
| head 15
```

### Geographic Distribution with IP and Region Detail

```spl
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json 
| iplocation src_ip
| stats count by src_ip, Country, Region
| sort -count
| head 20
```

### CVE Extraction from Suricata Signatures

```spl
index=honeypot sourcetype=suricata:json alert.signature=*CVE* NOT src_ip="172.31.*"
| rex field=alert.signature "(?<cve>CVE-\d{4}-\d+)"
| stats count by cve
| sort -count
```

### Full Suricata Signature Counts (Top 20)

```spl
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by alert.signature_id, alert.signature
| sort -count
| head 20
```

### Blocklist Reputation Hits (Dshield/Spamhaus/CINS)

```spl
index=honeypot sourcetype=suricata:json
(alert.signature_id="2402000" OR alert.signature_id="2400003" OR alert.signature_id="2400006" OR alert.signature="*CINS*" OR alert.signature="*DROP*")
NOT src_ip="172.31.*"
| stats dc(src_ip) as known_bad_ips, count as total_events
```

### Target Port Distribution (Suricata, External)

```spl
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by dest_port
| sort -count
| head 15
```

### Target Port Distribution (Non-Suricata Honeypots)

```spl
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats count by dest_port
| sort -count
| head 15
```

### Nmap Scan Signatures

```spl
index=honeypot sourcetype=suricata:json alert.signature="*NMAP*" NOT src_ip="172.31.*"
| stats count by alert.signature
| sort -count
| head 10
```

### p0f OS Fingerprinting (SYN Packets Only)

```spl
index=honeypot sourcetype=p0f:log mod="syn" subject="cli" os!="???" os!=""
| stats count by os
| sort -count
| head 15
```

### Cowrie Session Summary

```spl
index=honeypot sourcetype=cowrie
| stats count by eventid
| sort -count
```

### Cowrie Login Successes

```spl
index=honeypot sourcetype=cowrie eventid="cowrie.login.success"
| table _time, src_ip, username, password
| sort _time
```

### Cowrie Login Failures (Top Credential Pairs)

```spl
index=honeypot sourcetype=cowrie eventid="cowrie.login.failed"
| stats count by username, password
| sort -count
| head 20
```

### Cowrie Post-Exploitation Commands

```spl
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
| stats count by input, src_ip
| sort -count
| head 20
```

### Cowrie Commands by Input (Unique List)

```spl
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
| stats count by input
| sort -count
| head 30
```

### Malware Hashes (Cowrie File Downloads)

```spl
index=honeypot sourcetype=cowrie eventid="cowrie.session.file_download"
| table _time, src_ip, url, shasum, outfile
| sort _time
```

### Per-IP Full Cowrie Timeline

```spl
index=honeypot sourcetype=cowrie src_ip="[TARGET_IP]"
| sort _time
| table _time, eventid, username, password, input, url, shasum
```

### DoublePulsar Top Sources

```spl
index=honeypot sourcetype=suricata:json alert.signature="*DoublePulsar*" NOT src_ip="172.31.*"
| stats count by src_ip
| sort -count
| head 15
```

### EternalBlue Probe Signatures

```spl
index=honeypot sourcetype=suricata:json alert.signature="*ETERNALBLUE*" NOT src_ip="172.31.*"
| stats count by alert.signature, src_ip
| sort -count
| head 10
```

### Per-IP Suricata Signature Breakdown

```spl
index=honeypot sourcetype=suricata:json src_ip="[TARGET_IP]"
| stats count by alert.signature
| sort -count
| head 10
```

### IONOS Cluster Traffic Confirmation

```spl
index=honeypot sourcetype=suricata:json
(src_ip="31.70.75.115" OR src_ip="31.70.89.209" OR src_ip="31.70.75.109" OR src_ip="31.70.75.117" OR src_ip="31.70.78.114" OR src_ip="31.70.78.222" OR src_ip="31.70.75.104" OR src_ip="31.70.75.118" OR src_ip="31.70.77.205")
| stats count by src_ip, sourcetype
| sort src_ip
```

### Redis Honeypot Top Attacking IPs

```spl
index=honeypot sourcetype=redishoneypot:log
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
| head 10
```

### Dionaea Connection Types

```spl
index=honeypot sourcetype=dionaea
| stats count by connection.type
| sort -count
```

### ConPot ICS Protocol Activity

```spl
index=honeypot sourcetype=conpot
| stats count by sourcetype, src_ip
| sort -count
| head 15
```

### Tanner Web Honeypot — Top Requested Paths

```spl
index=honeypot sourcetype=tanner:json
| stats count by path
| sort -count
| head 25
```

### Tanner Web Honeypot — Top User-Agents

```spl
index=honeypot sourcetype=tanner:json
| stats count by method, "headers.user-agent"
| sort -count
| head 15
```

### Tanner Web Honeypot — POST Requests (Potential Exploit Payloads)

```spl
index=honeypot sourcetype=tanner:json method=POST
| table _time, path, "headers.user-agent"
```

### Per-IP Full Multi-Source Timeline

```spl
index=honeypot src_ip="[TARGET_IP]"
| sort _time
| table _time, sourcetype, src_ip, eventid, username, password, input, shasum, dest_port
```

### Suricata ICS/SCADA Signatures

```spl
index=honeypot sourcetype=suricata:json alert.signature="*SCADA*" OR alert.signature="*IEC-104*"
NOT src_ip="172.31.*"
| stats count by alert.signature, src_ip
| sort -count
```

### Suricata Cobalt Strike JARM-Related HTTP Activity

```spl
index=honeypot sourcetype=suricata:json
(src_ip="18.218.118.203" OR src_ip="3.132.26.232" OR src_ip="3.130.168.2" OR src_ip="3.129.187.38")
| stats count by sourcetype
| sort -count
```
````
