# INCIDENT REPORT

**Case ID:** 7

**Classification:** High Severity - Ransomware Extortion Attempt

**Status:** Closed

**Prepared by:** Prince Lassey

**Date Closed:** 2026-05-10

---

## Executive Summary

On 10 May 2026 at 23:14:16 UTC, a high-severity alert was triggered within the Splunk SIEM environment for "the company", indicating an automated ransomware extortion attempt targeting an exposed Elasticsearch instance at 
host 172.31.44.165. The attacker, operating from IP address 142.93.254.220 - a DigitalOcean cloud instance in Newark, New Jersey - sent a POST request to the Elasticsearch REST API endpoint `/read_me/_doc`, 
injecting a ransom note claiming the target's database had been deleted and demanding payment of 0.0041 BTC (approximately $260 USD at time of incident) to a specified Bitcoin wallet. A 48-hour payment deadline was 
imposed, with a contact email and external short-link domain included in the payload. Automated enrichment via the N8N SOAR pipeline - using Ollama, VirusTotal, and IPAPI - confirmed the source IP as malicious 
(flagged by 9 antivirus vendors), identified the embedded short-link domain `tli.sh` as a confirmed phishing domain (flagged by 5 vendors), and classified the event as a **True Positive**. Automated containment was 
triggered immediately upon the True Positve verdict: the source IP was added to the OPNsense `Dynamic_Blocklist` firewall alias, enforcing a block on both inbound (WAN) and outbound (LAN) traffic. The analyst, Prince Lassey, 
subsequently escalated the alert to a full DFIR-IRIS case, conducted IOC extraction and investigation, and confirmed no evidence of actual data deletion or exfiltration since it was a honeypot environment. 
The case is now closed. Remediation recommendations have been documented to prevent recurrence in production Elasticsearch deployments.

---

## Timeline

| Timestamp (UTC) | Event |
|---|---|
| 2026-05-10 23:14:16 | Attacker at 142.93.254.220 sends POST request to 172.31.44.165:9200/read_me/_doc containing ransom note payload |
| 2026-05-10 23:14:16 | Splunk saved search `Elasticsearch Ransom Note Attempt` fires - webhook POST to N8N |
| 2026-05-10 23:14:17 | N8N receives alert payload; AI Agent begins IOC enrichment via VirusTotal and IPAPI |
| 2026-05-10 23:16:00 | AI returns verdict: **True Positive**, severity: High - structured investigation report generated |
| 2026-05-10 23:16:46 | DFIR-IRIS alert created with full AI triage report as case description |
| 2026-05-10 23:16:46 | Slack notification delivered to SOC-automation channel with enriched alert details |
| 2026-05-10 23:16:47 | IF node evaluates True Positive verdict - OPNsense API call triggered |
| 2026-05-10 23:16:47 | Source IP 142.93.254.220 added to `Dynamic_Blocklist` OPNsense alias - WAN and LAN block applied |
| 2026-05-10 23:16:48 | Containment action posted to Slack and logged as note in DFIR-IRIS alert |
| 2026-05-10 23:20:00 | Alert assigned, escalated to full IRIS case, manual investigation begun |
| 2026-05-10 23:45:00 | IOCs extracted, investigation notes documented, remediation recommended |
| 2026-05-10 23:55:00 | Case closed with final verdict |

---

## Investigation

### Initial Alert

The Splunk detection rule `Elasticsearch Ransom Note Attempt` - built from patterns observed during the T-Pot honeypot observation period - fired against a POST request captured by the Tanner web honeypot service. 
The raw HTTP request was as follows:

```
POST /read_me/_doc HTTP/1.1
Host: 32.193.117.201:9200
User-Agent: Go-http-client/1.1
Content-Type: application/json

{
  "message": "Your database has been deleted from your server, but all the
  information remains stored on our cluster. To recover: send 0.0041 BTC to
  bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r, then email wendy.etabw@gmx.com
  with code 0SH7HH1Q72JL and your transaction ID. You have 48 hours.
  For More Info - https://tli.sh/73x1k"
}
```

The use of Go's native HTTP client (`Go-http-client/1.1`), the `/read_me/_doc` endpoint path, and the structured JSON ransom note payload are characteristic of **automated ransomware tooling** targeting misconfigured, 
publicly exposed Elasticsearch clusters. The attack requires no prior authentication as it exploits the absence of access controls on the Elasticsearch API.

### IOC Enrichment Results

| IOC | Type | Enrichment Result |
|---|---|---|
| 142.93.254.220 | IPv4 | 9 malicious vendors, 4 suspicious - flagged for malware and spam; DigitalOcean LLC Newark NJ; Let's Encrypt cert for deverun.com |
| tli.sh | Domain | 5 vendors - confirmed phishing; Cloudflare-registered; reputation score: 1/100 |
| wendy.etabw@gmx.com | Email | No VirusTotal data - GMX free email address used as anonymous contact point |
| bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r | Bitcoin wallet | No VirusTotal data - native Bitcoin address; track via blockchain explorer |

### Root Cause

The root cause is an **unauthenticated, internet-exposed Elasticsearch REST API**. Elasticsearch does not enforce authentication by default in older configurations. When the API is reachable from the public internet 
without access controls, any actor with knowledge of the API structure can write to indices, delete data, or - as in this case - inject ransom notes. The attacker did not need credentials, did not need to 
exploit a software vulnerability, and did not need any prior access to the system. The exposure itself was the vulnerability.

### Extent of Impact

Within the honeypot environment, no actual data was deleted or exfiltrated - the Elasticsearch instance contained no real data, and the ransom note is an automated injection rather than confirmation of prior data access. 
However, in a production environment with real data, this attack pattern is capable of:

- Deleting all Elasticsearch indices
- Injecting false recovery instructions
- Extorting payment with no guarantee of data return

The attack is a single-event detection (first seen = last seen: 23:14:16), consistent with automated tooling performing one-shot ransom note injection rather than an extended hands-on intrusion.

---

## Response and Remediation

### Automated Response (N8N SOAR Pipeline)

Upon TRUE_POSITIVE classification:

- Source IP `142.93.254.220` added to OPNsense `Tpot_threatintel` alias within 1 second of verdict
- Firewall rules applied - inbound block (WAN) and outbound block (LAN) active immediately
- Containment confirmed in OPNsense Firewall → Diagnostics → Aliases

### Manual Investigation Actions

Following automated containment, I:

1. Reviewed the full AI triage report and VirusTotal enrichment in DFIR-IRIS
2. Assigned the alert and escalated to a full investigation case
3. Extracted all IOCs from the ransom note payload:
   - Attacker IP: `142.93.254.220`
   - Bitcoin wallet: `bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r`
   - Contact email: `wendy.etabw@gmx.com`
   - Phishing domain: `tli.sh` / `https://tli.sh/73x1k`
4. Confirmed no evidence of prior data access or actual deletion within the honeypot
5. Documented investigation timeline notes in IRIS
6. Closed case with a True Positive verdict.

---

## Recommendations

The following actions are recommended to prevent this attack class from succeeding in any production environment running Elasticsearch:

**Immediate:**
- Block `142.93.254.220`, `tli.sh`, and `wendy.etabw@gmx.com` across all network and email gateways
- Audit all Elasticsearch instances for public internet exposure - port 9200 and 9300 should never be internet-facing
- Conduct an Elasticsearch data integrity audit to confirm no indices were modified or deleted prior to detection

**Short-term:**
- Enable Elasticsearch security features - RBAC (Role-Based Access Control) and API key authentication are disabled by default in some versions and must be explicitly enabled
- Restrict Elasticsearch API access to trusted internal IP addresses only via firewall allowlist - deny all external access by default
- Deploy Elasticsearch behind a reverse proxy with authentication if external access is genuinely required

**Ongoing:**
- Include Elasticsearch port scanning in regular vulnerability scanning schedules
- Add Elasticsearch API write events to SIEM monitoring - unexpected POST requests to `/_doc` endpoints from external IPs should trigger immediate alerts
- Implement index lifecycle management with automated snapshots - so that if data deletion does occur, recovery does not depend on paying a ransom

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Unauthenticated Elasticsearch API exposed to the internet |
| Impact | Data Destruction | T1485 | Attacker claims to have deleted the database contents |
| Impact | Financial Theft | T1657 | Bitcoin ransom demand with 48-hour deadline |
| Command and Control | Application Layer Protocol - Web Protocols | T1071.001 | HTTP POST used to deliver ransom note payload |

---

## Conclusion

The incident was an automated ransomware extortion attempt targeting a publicly exposed Elasticsearch instance, executed using known tooling and a well-documented attack pattern. The attack was detected by a custom 
Splunk detection rule, automatically triaged and enriched via the N8N-Gemini-VirusTotal pipeline, and contained at the network firewall layer within seconds of the verdict - prior to any analyst intervention.
The automated pipeline performed as designed. Containment was faster than any manual response could achieve, and the full audit trail - from raw alert to firewall block to IRIS case note - is preserved for review.
No production data was at risk in this environment. In a real deployment, an undetected version of this attack against a misconfigured Elasticsearch instance would result in data loss, downtime, and 
potential regulatory exposure. The detection, enrichment, and response capabilities demonstrated in this pipeline directly address that risk.

**Case Status: Closed**

**Final Verdict: True Positive**

**Analyst: Prince Lassey**
