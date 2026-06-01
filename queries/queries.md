## Claude and Splunk Queries

---

## Claude Queries

### 1.1 Reconnaissance & Scanning

```
"Query the tpot index and identify the top 10 IPs performing port scanning 
activity. For each IP, show which ports they scanned and which honeypots they 
triggered, ordered by total event count."

"Find all Suricata events with signature 2009582 (NMAP -sS scan). For each 
source IP, show their scan timing pattern — are they scanning continuously or 
in bursts?"

"Look at Honeytrap events and identify IPs that scanned more than 50 unique 
destination ports. These are likely performing comprehensive host discovery."
```

### 1.2 Credential & Brute-Force Analysis

```
"From Cowrie logs, extract all failed login attempts. What are the top 20 
username:password combinations attempted? Are any of these known default 
credentials for IoT devices like routers or cameras?"

"Identify IPs in the Cowrie logs that attempted more than 100 login attempts 
in under 60 seconds. Show their username and password patterns — are they 
using dictionaries or single-password spray techniques?"

"From Cowrie, find all successful logins (eventid cowrie.login.success). For 
each, trace the full session — what commands did the attacker run after 
gaining access?"
```

### 1.3 Exploitation & Payload Analysis

```
"Search the Dionaea logs for HTTP request bodies containing 'shell_exec' or 
'base64_decode'. Show me the decoded payloads where possible, and which IPs 
are sending them."

"Find all Suricata alerts for CVE-2024-4577 and CVE-2017-9841 (PHP 
exploitation). Correlate these with Dionaea HTTP logs from the same source IPs 
to see if exploitation attempts were successful."

"What is the full timeline of activity for IP 201.216.239.205? Show me every 
event across all honeypots in chronological order, including what service they 
hit, what credentials or commands they used, and any files they downloaded."
```

### 1.4 Post-Exploitation & Malware

```
"From Cowrie session file_download events, list all unique file hashes 
downloaded by attackers. Group IPs by which files they downloaded — are 
multiple IPs downloading the same payload? This suggests a coordinated campaign."

"In AdbHoney logs, find all instances of commands that include 'wget', 'curl', 
or 'chmod'. Extract the URLs being fetched and show me which IPs are fetching them."

"Are there any IPs that triggered both Cowrie (SSH brute-force) AND 
Suricata EternalBlue alerts (SID 2024766)? These dual-vector attackers may 
represent more sophisticated operators."
```

### 1.5 Infrastructure & Campaign Correlation

```
"Group all attacking IPs by their ASN. Which cloud providers are hosting the 
most attack infrastructure? Show me the top 5 ASNs and a representative sample 
of IPs from each."

"Are there IPs from the Attacker Source IP Top 10 list that appear across 
multiple honeypots? A single IP hitting SSH, SMB, and HTTP suggests an 
automated multi-vector scanner."

"Look at the attack timeline. Was the spike in January–April 2026 driven by 
a specific attack type or honeypot? Did new CVEs or new IPs appear during 
this period, or was it existing actors scaling up?"
```

### 1.6 IOC Generation

```
"Generate a list of all unique source IPs that triggered at least 3 different 
Suricata alert signatures. Format the output as a CSV with columns: IP, ASN, 
Country, Total Events, Alert Types."

"Extract all unique file hashes from Cowrie downloads and Dionaea captures. 
Format as a list suitable for VirusTotal bulk lookup."

"Find all URLs or domains that appeared in Cowrie wget/curl commands or 
Dionaea HTTP referrer headers. These are potential C2 or dropper infrastructure."
```

---

## 2\. Splunk Queries

```spl
-- Index discovery
| eventcount summarize=false index=* | dedup index | table index

-- All sourcetypes and event counts
index=honeypot | stats count by sourcetype | sort -count

-- Top 20 attacking IPs (all sources)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats count by src_ip | sort -count | head 20

-- Total unique IPs and events (application layer)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats dc(src_ip) as unique_ips, count as total_events

-- Total unique IPs and events (Suricata, external only)
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats dc(src_ip) as unique_ips, count as total_events

-- Geographic distribution (top 15 countries)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json
| iplocation src_ip | stats count by Country | sort -count | head 15

-- Geographic distribution with IP and region detail
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| iplocation src_ip | stats count by src_ip, Country, Region | sort -count | head 20

-- CVE extraction from Suricata signatures
index=honeypot sourcetype=suricata:json alert.signature=*CVE* NOT src_ip="172.31.*"
| rex field=alert.signature "(?<cve>CVE-\d{4}-\d+)"
| stats count by cve | sort -count

-- Full Suricata signature counts (top 20)
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by alert.signature_id, alert.signature | sort -count | head 20

-- Blocklist reputation hits (Dshield/Spamhaus/CINS)
index=honeypot sourcetype=suricata:json
(alert.signature_id="2402000" OR alert.signature_id="2400003"
 OR alert.signature_id="2400006" OR alert.signature="*CINS*" OR alert.signature="*DROP*")
NOT src_ip="172.31.*"
| stats dc(src_ip) as known_bad_ips, count as total_events

-- Target port distribution (Suricata, external)
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by dest_port | sort -count | head 15

-- Target port distribution (non-Suricata honeypots)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats count by dest_port | sort -count | head 15

-- Nmap scan signatures
index=honeypot sourcetype=suricata:json alert.signature="*NMAP*"
NOT src_ip="172.31.*" | stats count by alert.signature | sort -count | head 10

-- p0f OS fingerprinting (SYN packets only)
index=honeypot sourcetype=p0f:log mod="syn" subject="cli" os!="???" os!=""
| stats count by os | sort -count | head 15

-- Cowrie session summary
index=honeypot sourcetype=cowrie | stats count by eventid | sort -count

-- Cowrie login successes
index=honeypot sourcetype=cowrie eventid="cowrie.login.success"
| table _time, src_ip, username, password | sort _time

-- Cowrie login failures (top credential pairs)
index=honeypot sourcetype=cowrie eventid="cowrie.login.failed"
| stats count by username, password | sort -count | head 20

-- Cowrie post-exploitation commands
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
| stats count by input, src_ip | sort -count | head 20

-- Cowrie commands by input (unique list)
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
| stats count by input | sort -count | head 30

-- Malware hashes (Cowrie file downloads)
index=honeypot sourcetype=cowrie eventid="cowrie.session.file_download"
| table _time, src_ip, url, shasum, outfile | sort _time

-- Per-IP full Cowrie timeline
index=honeypot sourcetype=cowrie src_ip="[TARGET_IP]"
| sort _time | table _time, eventid, username, password, input, url, shasum

-- DoublePulsar top sources
index=honeypot sourcetype=suricata:json alert.signature="*DoublePulsar*" NOT src_ip="172.31.*"
| stats count by src_ip | sort -count | head 15

-- EternalBlue probe signatures
index=honeypot sourcetype=suricata:json alert.signature="*ETERNALBLUE*" NOT src_ip="172.31.*"
| stats count by alert.signature, src_ip | sort -count | head 10

-- Per-IP Suricata signature breakdown
index=honeypot sourcetype=suricata:json src_ip="[TARGET_IP]"
| stats count by alert.signature | sort -count | head 10

-- IONOS cluster traffic confirmation
index=honeypot sourcetype=suricata:json
(src_ip="31.70.75.115" OR src_ip="31.70.89.209" OR src_ip="31.70.75.109"
 OR src_ip="31.70.75.117" OR src_ip="31.70.78.114" OR src_ip="31.70.78.222"
 OR src_ip="31.70.75.104" OR src_ip="31.70.75.118" OR src_ip="31.70.77.205")
| stats count by src_ip, sourcetype | sort src_ip

-- Redis honeypot top attacking IPs
index=honeypot sourcetype=redishoneypot:log
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort -count | head 10

-- Dionaea connection types
index=honeypot sourcetype=dionaea | stats count by connection.type | sort -count

-- ConPot ICS protocol activity
index=honeypot sourcetype=conpot | stats count by sourcetype, src_ip | sort -count | head 15

-- Tanner web honeypot — top requested paths
index=honeypot sourcetype=tanner:json | stats count by path | sort -count | head 25

-- Tanner web honeypot — top user-agents
index=honeypot sourcetype=tanner:json
| stats count by method, "headers.user-agent" | sort -count | head 15

-- Tanner web honeypot — POST requests (potential exploit payloads)
index=honeypot sourcetype=tanner:json method=POST | table _time, "peer.ip", path, "headers.user-agent"

-- Per-IP full multi-source timeline
index=honeypot src_ip="[TARGET_IP]"
| sort _time | table _time, sourcetype, src_ip, eventid, username, password, input, shasum, dest_port

-- Suricata ICS/SCADA signatures
index=honeypot sourcetype=suricata:json alert.signature="*SCADA*" OR alert.signature="*IEC-104*"
NOT src_ip="172.31.*" | stats count by alert.signature, src_ip | sort -count

-- Suricata Cobalt Strike JARM-related HTTP activity
index=honeypot sourcetype=suricata:json
(src_ip="18.218.118.203" OR src_ip="3.132.26.232" OR src_ip="3.130.168.2" OR src_ip="3.129.187.38")
| stats count by sourcetype | sort -count
```
