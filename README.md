# T-Pot Honeypot Deployment on AWS Cloud: ELK Stack, Splunk SIEM, Tailscale, Claude AI & VirusTotal Threat Intelligence (MCPs)

> *Multi-honeypot telemetry > ELK analysis > Splunk SIEM forwarding over Tailscale > AI-powered threat hunting with Claude & VirusTotal enrichment*

---

## What Makes This Different

Most honeypot projects stop at installed T-Pot and collecting data from the already existing Kibana dashboard. This one doesn't.

Here's what this project adds on top of a standard T-Pot deployment:

-   **Splunk SIEM integration over a private Tailscale mesh network:** no public Splunk port exposed and no VPN headache. The universal forwarder sends logs from the EC2 instance directly to a local Splunk instance via Tailscale IP for local log storage.
-   **AI-powered log analysis via MCP (Model Context Protocol):** Claude AI is connected directly to Splunk using the Splunk MCP server. That means natural language queries against live honeypot logs, automated correlation, and threat enrichment.. all from a conversation.
-   **VirusTotal enrichment on all captured malware hashes:** every payload dropped by attackers (Cowrie SFTP uploads, ADBHoney ARM binaries, Dionaea EternalBlue captures) was looked up on VirusTotal. 51 hashes total. 3 were not in VirusTotal at all.
-   **A full structured threat intelligence report:** Not a screenshot dump. A proper TI report covering attack timelines, coordinated actor attribution, CVE analysis, MITRE ATT&CK mapping, IOCs, and recommendations.

This deployment also feeds data into a companion AI Augmented SOC Detection Engineering lab project (separate repo) where the captured IOCs and attack patterns are used to build and validate detection rules in my SOC homelab.

---

## Table of Contents

1.  [Project Overview](#1-project-overview)
2.  [Architecture](#2-architecture)
3.  [EC2 Instance Setup](#3-ec2-instance-setup)
    -   3.1 [IAM User & Instance Launch](#31-iam-user--instance-launch)
    -   3.2 [Elastic IP & SSH Access](#32-elastic-ip--ssh-access)
    -   3.3 [User Accounts & Decoy Environment](#33-user-accounts--decoy-environment)
    -   3.4 [Docker Installation](#34-docker-installation)
4.  [T-Pot Honeypot Installation](#4-t-pot-honeypot-installation)
    -   4.1 [Installation & Configuration](#41-installation--configuration)
    -   4.2 [Security Group Rules](#42-security-group-rules)
    -   4.3 [Verifying the Web UI](#43-verifying-the-web-ui)
    -   4.4 [Opening to the Internet](#44-opening-to-the-internet)
5.  [Log Decompression & Preparation](#5-log-decompression--preparation)
6.  [Splunk SIEM Setup](#6-splunk-siem-setup)
    -   6.1 [Installing Splunk Enterprise](#61-installing-splunk-enterprise)
    -   6.2 [Creating the Honeypot Index](#62-creating-the-honeypot-index)
7.  [Tailscale Network Setup](#7-tailscale-network-setup)
8.  [Splunk Universal Forwarder](#8-splunk-universal-forwarder)
    -   8.1 [Installation & Boot Configuration](#81-installation--boot-configuration)
    -   8.2 [inputs.conf Configuration](#82-inputsconf-configuration)
    -   8.3 [Troubleshooting Ingestion](#83-troubleshooting-ingestion)
9.  [Claude AI + Splunk MCP Integration](#9-claude-ai--splunk-mcp-integration)
    -   9.1 [Installing Claude Desktop (Linux)](#91-installing-claude-desktop-linux)
    -   9.2 [Splunk MCP Server Setup](#92-splunk-mcp-server-setup)
    -   9.3 [MCP Configuration File](#93-mcp-configuration-file)
10.  [Splunk Queries - Detection Engineering Reference](#10-splunk-queries--detection-engineering-reference)
     -   10.1 [Discovery & Volume Queries](#101-discovery--volume-queries)
     -   10.2 [Attack Surface Queries](#102-attack-surface-queries)
     -   10.3 [Cowrie SSH/Telnet Queries](#103-cowrie-sshtelnet-queries)
     -   10.4 [Threat Intelligence Queries](#104-threat-intelligence-queries)
     -   10.5 [Campaign & Attribution Queries](#105-campaign--attribution-queries)
11.  [Kibana - Key Dashboard Queries](#11-kibana--key-dashboard-queries)
12.  [Threat Intelligence Report](#12-threat-intelligence-report)
13.  [Key Findings Summary](#13-key-findings-summary)
14.  [Repository Structure](#14-repository-structure)

---

## 1\. Project Overview

| Parameter | Value |
| --- | --- |
| Platform | T-Pot CE v24.x (Deutsche Telekom) |
| Deployment | AWS EC2 - `m7i-flex.large` (2 vCPU, 8 GB RAM), 128 GB storage |
| Region | us-east-1 (United States - N. Virginia) |
| OS | Ubuntu |
| Observation period | 21 days |
| Total events captured | ~3.47 million |
| Unique attacker IPs | 20,727+ |
| Honeypot services | 20 active sourcetypes |
| SIEM | ELK and Splunk Enterprise (local VM, forwarded via Tailscale) |
| AI integration | Claude AI via Splunk MCP server |
| Malware hashes analysed | 51 (Cowrie + ADBHoney + Dionaea) |
| Local VM | Ubuntu |

---

## 2\. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   AWS EC2 Instance                       │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              T-Pot CE (Docker)                   │   │
│  │  Cowrie │ Dionaea │ ADBHoney │ ConPot │ Heralding│   │
│  │  Redis  │ Mailoney│ Tanner  │ Suricata│ p0f      │   │
│  └─────────────────┬───────────────────────────────┘   │
│                    │ logs → /tpotce/data/*/log           │
│  ┌─────────────────▼───────────────────────────────┐   │
│  │        Splunk Universal Forwarder                │   │
│  │  inputs.conf → index=honeypot                    │   │
│  └─────────────────┬───────────────────────────────┘   │
└────────────────────┼────────────────────────────────────┘
                     │ port 9997 (encrypted, Tailscale)
          ┌──────────▼──────────┐
          │   Tailscale Mesh    │
          │  (private network)  │
          └──────────┬──────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Local VM (Ubuntu)                  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Splunk Enterprise                       │  │
│  │  index=honeypot │ port 9997 receiver              │  │
│  └─────────────────┬────────────────────────────────┘  │
│                    │                                    │
│  ┌─────────────────▼────────────────────────────────┐  │
│  │        Claude Desktop (Linux)                     │  │
│  │   Splunk MCP Server → natural language queries    │  │
│  │   VirusTotal API  → hash and IP enrichment            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 3\. EC2 Instance Setup

### 3.1 IAM User & Instance Launch

Started by creating a dedicated IAM user rather than using the root account, a standard practice and my first real AWS project principle: never use root for operational work.

![](images/media/image1.png)

![](images/media/image2.png)

![](images/media/image3.png)

![](images/media/image4.png)

![](images/media/image5.png)

For the instance itself:

-   **AMI:** Ubuntu (latest LTS)
-   **Instance type:** `m7i-flex.large` - 2 vCPU, 8 GB RAM. Would have preferred 16 GB honestly, but this was the highest I had free tier access to and it held up just fine.
-   **Storage:** 128 GB (gp3) - T-Pot runs a full ELK stack in Docker so it eats disk fast
-   **Key pair:** Created a new `.pem` key pair for SSH access

![](images/media/image7.png)  
![](images/media/image10.png) 
![](images/media/image8.png)

For network settings during launch, I created a new security group (`launch-wizard-1`) with a single rule allowing SSH from my IP only. The plan was to lock it down tight first and open it up for attacks only after everything was verified working.

![](images/media/image9.png) 
![](images/media/image11.png)

### 3.2 Elastic IP & SSH Access

Before connecting to the instance for the first time, I allocated an Elastic IP, AWS's feature for a static public IP that doesn't change when the instance restarts. Really important for a long-running honeypot so you're not chasing a new IP every time there's a reboot.

Steps:

1.  EC2 Console > Elastic IPs > Allocate Elastic IP address
2.  Associate it to the running instance

![](files/images/media/image13.png) 
![](images/media/image14.png) 
![](images/media/image15.png)

Then connected via SSH:

```bash
ssh -i "myhoney.pem" ubuntu@<elastic-ip>
```

![](images/media/image16.png) 
![](images/media/image17.png)

First thing after getting in:

```bash
sudo apt update && sudo apt upgrade -y
```

![](images/media/image18.png)

### 3.3 User Account

I created a main user `apostrophe` with sudo permissions. 

```bash
sudo adduser apostrophe
sudo usermod -aG sudo apostrophe
```

Then logged out and back in as `apostrophe` for all subsequent work.

![](images/media/image19.png)

The `~/.ssh/authorized_keys` file for `apostrophe` was either missing or owned by root. The server does not have the ssh public key for the user apostrophe.

To resolve the issue, I had to add my public key to the user apostrophe. Logged in as ubuntu, I acceesed and copied the public key and logged back in as apostrophe and created the file authorized\_keys within ~/.ssh/ and pasted the public key.  

```bash
sudo mkdir -p /home/apostrophe/.ssh
sudo cp -r /home/ubuntu/.ssh /home/apostrophe/
sudo chown -R apostrophe:apostrophe /home/apostrophe/.ssh
sudo chmod 700 /home/apostrophe/.ssh
sudo chmod 600 /home/apostrophe/.ssh/authorized_keys
```

![](images/media/image25.png) 
![](images/media/image26.png) 
![](images/media/image27.png)

### 3.4 Docker Installation

![](images/media/image22.png)

T-Pot runs entirely in Docker, so that had to go on first. Downloaded the install script from the kitpro docker guide:

```bash
curl -fsSL https://wiki.kitpro.us/en/articles/docker-script -o install-docker.sh
chmod +x install-docker.sh
sudo ./install-docker.sh
```

After install, log out and back in to pick up the docker group membership, then verify:

```bash
docker --version
docker compose version
```

![](images/media/image30.png)

---

## 4\. T-Pot Honeypot Installation

![](images/media/image37.png)

### 4.1 Installation & Configuration

Cloned the official T-Pot CE repository from Deutsche Telekom Security into `/opt/`:

```bash
cd /opt
sudo git clone https://github.com/telekom-security/tpotce.git
cd tpotce
sudo ./install.sh
```

![](images/media/image38.png) 
![](images/media/image39.png)

Installation options selected:

-   **Type:** Hive - the standard full install with maximum capabilities
-   **Web UI credentials:** Set a username and password (not writing them here obviously lol)

![](images/media/image40.png) 
![](images/media/image41.png)

The installer pulls all the Docker images, configures the ELK stack, and changes the main SSH port. In my case it moved to **port 64295** - the old port 22 becomes the Cowrie SSH honeypot.

After install completed, rebooted the instance:

```bash
sudo reboot
```

![](images/media/image42.png)

### 4.2 Security Group Rules

Before reconnecting, updated the EC2 security group inbound rules:

| Port Range | Protocol | Source | Purpose |
| --- | --- | --- | --- |
| 64295 | TCP | My IP only | Admin SSH access |
| 64297 | TCP | My IP only | T-Pot Web UI |
| 22 | TCP | 0.0.0.0/0 | Cowrie SSH honeypot |

The logic: everything on the admin ports is locked to my IP, everything on the honeypot ports is wide open to the internet.

Reconnected using the new port:

```bash
ssh -i "myhoney.pem" -p 64295 apostrophe@<elastic-ip>
```

### 4.3 Verifying the Web UI

Accessed the T-Pot web interface at `https://<elastic-ip>:64297`. Kept getting a "site can't be reached" error. Everything looked fine in the backend though:

```bash
sudo systemctl status tpot
sudo docker ps
```

![](images/media/image48.png)

All containers were running. Turned out the issue was that my IP filter in the security group rule was too restrictive - a quirk with how AWS handles source IP matching on some browser setups. Fixed it by temporarily allowing `0.0.0.0/0` on port 64297, confirmed the UI loaded, then immediately locked it back to my IP.

![](images/media/image49.png)

First time logging in I had a credential issue. The exclamation mark in my intended username (`questionmark!`) was being silently dropped by the T-Pot user management script. When I thought everything was going well... nope. Used the `genuser.sh` script from the tpot directory to create a clean new credential set:

```bash
cd /opt/tpotce
sudo ./genuser.sh
```

![](images/media/image50.png) ![](images/media/image51.png)

After that, the UI loaded clean. Confirmed all the built-in tools were working:

-   Attack Map 
-   CyberChef
-   Spiderfoot
-   Kibana (was still loading - takes a couple of minutes on first boot)

![](images/media/image52.png) ![](images/media/image53.png) ![](images/media/image54.png) ![](images/media/image55.png) ![](images/media/image56.png)

### 4.4 Opening to the Internet

![](images/media/image57.png)

Once everything was confirmed working, updated the security group to allow all inbound traffic on ports 0–64000. Rebooted the instance and within a few minutes, hits started coming in.

-   First hits: within minutes of going live
-   After 7 hours: visible attack volume across multiple honeypots
-   After 2 weeks: thousands of events per day, multiple countries

![](images/media/image59.png) ![](images/media/image60.png) ![](images/media/image61.png) ![](images/media/image62.png)

Edited the inbound rules back (restricted to my IP only) when it was time to do the analysis cleanly.

![](images/media/image63.png)

---

## 5\. Log Decompression & Preparation

T-Pot's internal logrotate compresses older logs to `.gz`. Splunk's Universal Forwarder can read `.gz` files but the ELK stack components don't always play well — and more importantly, I wanted to make sure everything was readable before pointing Splunk at it.

Found all compressed log files:

```bash
sudo find /home/apostrophe/tpotce/data/*/log -name "*.gz"
```

![](images/media/image64.png)

Decompressed everything while keeping the originals (the `-k` flag) and skipping the ELK directory (those are internal T-Pot indexes, not attack logs):

```bash
sudo find /home/apostrophe/tpotce/data \
  -path "*/elk/*" -prune \
  -o -name "*.gz" -exec gunzip -kf {} \;
```

![](images/media/image65.png)

Verified the output:

```bash
sudo find /home/apostrophe/tpotce/data \
  -path "*/elk/*" -prune \
  -o \( -name "*.json" -o -name "*.csv" -o -name "*.log" \) -print | head -10
```

![](images/media/image66.png)

Worked.

---

## 6\. Splunk SIEM Setup

### 6.1 Installing Splunk Enterprise

Installed Splunk Enterprise on my local VM using the `.deb` package:

```bash
sudo dpkg -i splunk*.deb
cd /opt/splunk
sudo -u splunk ./bin/splunk start
```

![](images/media/image67.png) ![](images/media/image68.png) ![](images/media/image69.png) ![](images/media/image70.png)

Enabled Splunk to start automatically on boot:

```bash
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
sudo systemctl enable Splunk
sudo systemctl start Splunk
```

Verified it was running at `http://localhost:8000`.

![](images/media/image72.png)

### 6.2 Creating the Honeypot Index

In the Splunk web UI:

Settings > Indexes > New Index

| Setting | Value |
| --- | --- |
| Index Name | `honeypot` |

![](images/media/image75.png)

Then configured Splunk to receive forwarded data:

Settings > Forwarding and Receiving > Configure Receiving > New Receiving Port: **9997**

![](images/media/image78.png)

Verified Splunk was listening:

```bash
sudo netstat -tlnp | grep 9997
```

![](images/media/image79.png)

---

## 7\. Tailscale Network Setup

Rather than opening a Splunk port to the internet or running a full VPN, I used **Tailscale** to create a private mesh network between the EC2 instance and my local VM. The forwarder sends to the EC2's Tailscale IP, no public exposure of Splunk at all.

Installed Tailscale on both machines:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

![](images/media/image80.png)

```bash
sudo tailscale up
```

![](images/media/image81.png)

Logged into the same Tailscale account on both. After auth, each machine gets a stable private IP in the `100.x.x.x` range that never changes.

![](images/media/image82.png) ![](images/media/image83.png) ![](images/media/image84.png)

One thing to note: I masked the Tailscale IP in the documentation screenshots since I was planning to use a Tailscale Funnel for another project, didn't want to expose that IP unnecessarily.

Verified connectivity between the two machines:

![](images/media/image85.png)

```bash
ping <tailscale-ip-of-splunk-vm>
```

Success. The EC2 instance could now reach the Splunk receiver on the local VM over the private network.

---

## 8\. Splunk Universal Forwarder

### 8.1 Installation & Boot Configuration

Downloaded and installed the [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html) on the EC2 instance:

![](images/media/image86.png)

![](images/media/image87.png)

```bash
sudo tar -xvzf splunkforwarder*.tgz
```

![](images/media/image88.png)

```bash
sudo mv splunkforwarder /opt/
cd /opt/splunkforwarder/bin
```

![](images/media/image89.png)

```bash
sudo ./splunk start --accept-license
```

![](images/media/image90.png)

I then enabled bootstart to make sure the forwarder survives reboots automatically.  

```bash
sudo ./splunk enable boot-start
```

Then I run

```bash
sudo ./splunk status  
```

but it returned an error which I fixed by using the splunkfwd user to run those commands.

```bash
sudo -u splunkfwd ./splunk status  
```

The forwarder was not started yet

![](images/media/image91.png)

Pointed the forwarder at the Splunk receiver using the Tailscale IP:

```bash
sudo ./splunk add forward-server <tailscale-ip-of-splunk>:9997
```

but listing the forwarders showed configured but inactive. I had to start splunkforwarder first.  

![](images/media/image92.png)

Running `enable boot-start` as root, Splunk records root as the boot user in the systemd unit file and then refuses to start as the `splunkfwd` user.

![](images/media/image93.png)

To fix it, this is what I did:

```bash
# Fixed ownership
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder
```

```bash
# Removed the bad systemd unit
sudo /opt/splunkforwarder/bin/splunk disable boot-start
```

```bash
# Re-enabled with the correct user
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunkfwd
```

```bash
# Started via systemd
sudo systemctl start SplunkForwarder
sudo systemctl status SplunkForwarder
```

![](images/media/image94.png)

I then run

```
./splunk list forward-server  
```

which asked me to login using the username and password I had created earlier on. Now, I had an active forward.  

![](images/media/image95.png)

### 8.2 inputs.conf Configuration

The inputs.conf file lives at:

```
/opt/splunkforwarder/etc/apps/search/local/inputs.conf
```

Not `/opt/splunkforwarder/etc/system/local/inputs.conf` - that path exists but the apps path is where it actually takes effect. Learned that one the hard way lol.

![](images/media/image96.png)

The full configuration is in [`config/inputs.conf`](config/inputs.conf) in this repo. Here's what each parameter does:

| Parameter | Value | Purpose |
| --- | --- | --- |
| `[monitor://...]` | `/home/apostrophe/tpotce/data/*/log` | Monitors log directories for all honeypot services |
| `disabled` | `false` | Forwarder is active |
| `index` | `honeypot` | Routes all events to the dedicated honeypot index |
| `followTail` | `0` | Reads existing files from byte 0 — ensures complete historical ingestion on first run, then automatically transitions to real-time tailing |
| `crcSalt` | `<SOURCE>` | Includes the full file path in Splunk's checksum. Critical: ensures logrotate-numbered copies (`cowrie.json.1`, `suricata.csv.3`) are treated as unique inputs rather than duplicates of the active file |
| `whitelist` | <code>\.(csv\|log\|json)(\.\d+)?$</code> | log |
| `sourcetype` | Per-honeypot (see config) | Each honeypot has its own sourcetype for proper field extraction |

**The single-stanza mistake:** My first attempt used one wildcard stanza with `sourcetype = tpot:logs` for everything. Zero events showed up. The issue is that each honeypot produces differently structured logs - JSON, CSV, plain text and Splunk's field extraction is tied to sourcetype. Fixing it meant giving every honeypot its own stanza with its specific sourcetype like you see below

![](images/media/image98.png) ![](images/media/image99.png)

### 8.3 Troubleshooting Ingestion

If ingestion isn't working:

```bash
# Check forwarder is running
sudo systemctl status SplunkForwarder

# Verify forward server is configured and active
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk list forward-server

# Check forwarder logs for errors
sudo tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log

# Test connectivity to Splunk receiver
nc -zv <tailscale-ip> 9997
```

In Splunk, confirm events are arriving:

```spl
index=honeypot | head 10
```

---

## 9\. Claude AI + Splunk MCP Integration

This is the part that makes this project a bit different from the usual T-Pot write-up. Instead of just clicking around Kibana, I connected Claude AI directly to Splunk using the **Model Context Protocol (MCP)** which lets Claude issue real Splunk queries, read the results, and reason over them in natural language. Most importantly, I did this as a test for my SOC automation project which I plan to rather use a local AI deployment as my SOC assistant.

### 9.1 Installing Claude Desktop (Linux)

Claude Desktop doesn't have an official Linux build yet, so used the community Debian release:

```bash
# Prerequisites
sudo apt update && sudo apt upgrade -y
```

![](images/media/image100.png)

```bash
# Node.js (required for MCP servers)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

![](images/media/image101.png)

```bash
# Verify
node --version
npx --version
```

![](images/media/image102.png)

Downloaded the `.deb` from: [https://github.com/aaddrick/claude-desktop-debian/releases](https://github.com/aaddrick/claude-desktop-debian/releases)

![](images/media/image104.png)

```bash
sudo dpkg -i claude-desktop-*-amd64.deb
```

![](images/media/image105.png) ![](images/media/image106.png) ![](images/media/image109.png)

### 9.2 Splunk MCP Server Setup

In Splunk Enterprise:

**1\. Install the Splunk MCP Server app** from Splunkbase (search: "MCP Server")

![](images/media/image110.png)

**2\. Create an `mcp_user` role:**

Settings > Roles > New Role

-   Inherit from: `user`
-   Add capabilities: all `mcp_*` capabilities

![](images/media/image112.png) ![](images/media/image113.png) ![](images/media/image114.png)

**3\. Create an `mcp_user_1` account and assign it the `mcp_user` role**

![](images/media/image115.png) ![](images/media/image116.png) ![](images/media/image117.png)

**4\. Generate an MCP authentication token** for `mcp_user_1`:

Settings > Tokens > New Token

![](images/media/image118.png) ![](images/media/image119.png) ![](images/media/image121.png)

Copy the token immediately. Once you close that page it's gone forever and you'll have to generate a new one.

**5\. Restart Splunk** (Settings > Server Controls > Restart Splunk)

### 9.3 MCP Configuration File

The Claude Desktop config lives at:

```
~/.config/Claude/claude_desktop_config.json
```

The full config.. with Virustotal MCP is in [`config/claude_desktop_config.json`](config/claude_desktop_config.json). Below shows that for Splunk.

```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://192.168.56.112:8089/services/mcp",
        "--header",
        "Authorization: Bearer <token>"
      ],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
      }
    }
  }
}
```

![](images/media/image122.png)

Note that the token must be pasted after Bearer as seen below. Save it afterwards

![](images/media/image123.png)

After saving the config, restart Claude Desktop:

```bash
sudo pkill -f claude-desktop
claude-desktop &
```

![](images/media/image125.png) ![](images/media/image126.png)

What data do I have currently indexed in splunk? ![](images/media/image127.png)  
Query the honeypot index and identify the top 10 IPs performing port scanning activity. For each IP, show which ports they scanned and which honeypots they triggered, ordered by total event count.  

![](images/media/image128.png)

---

## 10\. Splunk Queries - Detection Engineering Reference

All queries run against `index=honeypot`. These are the core queries used throughout the analysis and serve as a starting point for detection rule development.

### 10.1 Discovery  Queries

![](images/media/image129.png)

```spl
-- Total unique IPs and events (application-layer honeypots)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats dc(src_ip) as unique_ips, count as total_events

-- Total unique IPs and events (Suricata IDS, external only)
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats dc(src_ip) as unique_ips, count as total_events
```

### 10.2 Attack Surface Queries

![](images/media/image130.png)

```spl
-- Top 20 attacking IPs
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json sourcetype!=fatt:json
| stats count by src_ip | sort -count | head 20

-- Geographic distribution (top 15 countries)
index=honeypot sourcetype!=p0f:log sourcetype!=suricata:json
| iplocation src_ip | stats count by Country | sort -count | head 15

-- Target port distribution (Suricata, external IPs)
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by dest_port | sort -count | head 15

-- Top Suricata signatures fired
index=honeypot sourcetype=suricata:json NOT src_ip="172.31.*" NOT src_ip="169.254.*"
| stats count by alert.signature_id, alert.signature | sort -count | head 20

-- CVE extraction from Suricata alerts
index=honeypot sourcetype=suricata:json alert.signature=*CVE* NOT src_ip="172.31.*"
| rex field=alert.signature "(?<cve>CVE-\d{4}-\d+)"
| stats count by cve | sort -count

-- Blocklist hit rate (Dshield / Spamhaus / CINS)
index=honeypot sourcetype=suricata:json
  (alert.signature="*Dshield*" OR alert.signature="*Spamhaus*" OR alert.signature="*CINS*")
  NOT src_ip="172.31.*"
| stats dc(src_ip) as blocklisted_ips, count as events

-- p0f OS fingerprinting (attacker OS distribution)
index=honeypot sourcetype=p0f:log mod="syn" subject="cli" os!="???" os!=""
| stats count by os | sort -count | head 15
```

### 10.3 Cowrie SSH/Telnet Queries

![](images/media/image131.png)

```spl
-- Session event summary
index=honeypot sourcetype=cowrie | stats count by eventid | sort -count

-- All successful logins
index=honeypot sourcetype=cowrie eventid="cowrie.login.success"
| table _time, src_ip, username, password | sort _time

-- Top credential pairs attempted (brute-force wordlist analysis)
index=honeypot sourcetype=cowrie eventid="cowrie.login.failed"
| stats count by username, password | sort -count | head 20

-- Post-exploitation commands
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
| stats count by input | sort -count | head 30

-- Malware payload hashes (file downloads via Cowrie)
index=honeypot sourcetype=cowrie eventid="cowrie.session.file_download"
| table _time, src_ip, url, shasum, outfile | sort _time

-- Full timeline for a specific IP
index=honeypot sourcetype=cowrie src_ip="<TARGET_IP>"
| sort _time | table _time, eventid, username, password, input, url, shasum
```

### 10.4 Threat Intelligence Queries

![](images/media/image133.png)

```spl
-- DoublePulsar/EternalBlue scanning — top source IPs
index=honeypot sourcetype=suricata:json alert.signature="*DoublePulsar*" NOT src_ip="172.31.*"
| stats count by src_ip | sort -count | head 15

-- ICS/SCADA protocol targeting (IEC-104)
index=honeypot sourcetype=suricata:json
  (alert.signature="*SCADA*" OR alert.signature="*IEC-104*")
  NOT src_ip="172.31.*"
| stats count by alert.signature, src_ip | sort -count

-- Cobalt Strike JARM candidates (multi-source check)
index=honeypot
  (src_ip="18.218.118.203" OR src_ip="3.132.26.232" OR
   src_ip="3.130.168.2" OR src_ip="3.129.187.38")
| stats count by src_ip, sourcetype | sort -count

-- Redis honeypot top attackers
index=honeypot sourcetype=redishoneypot:log
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip | sort -count | head 10

-- Tanner web honeypot — top URL paths targeted
index=honeypot sourcetype=tanner:json | stats count by path | sort -count | head 20

-- Tanner web honeypot — user-agent analysis
index=honeypot sourcetype=tanner:json
| stats count by method, "headers.user-agent" | sort -count | head 15

-- ADB honeypot source IPs
index=honeypot sourcetype=adbhoney
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip | sort -count | head 10
```

### 10.5 Campaign & Attribution Queries

![](images/media/image134.png)

```spl
-- IONOS fleet detection (coordinated VPS campaign)
index=honeypot
  (src_ip="31.70.75.115" OR src_ip="31.70.89.209" OR src_ip="31.70.75.109"
   OR src_ip="31.70.75.117" OR src_ip="31.70.78.114" OR src_ip="31.70.78.222"
   OR src_ip="31.70.75.104" OR src_ip="31.70.75.118" OR src_ip="31.70.77.205")
| stats count by src_ip | sort -count

-- Coordinated actor pair (shared credentials detection)
index=honeypot sourcetype=cowrie eventid="cowrie.login.success"
  (src_ip="81.9.145.130" OR src_ip="197.140.11.157")
| sort _time | table _time, src_ip, eventid, username, password

-- 2026-05-24 mass compromise wave timeline
index=honeypot sourcetype=cowrie eventid="cowrie.login.success"
| eval date=strftime(_time,"%Y-%m-%d") | where date="2026-05-24"
| sort _time | table _time, src_ip, username, password

-- mdrfckr SSH key injection detection
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
  input="*mdrfckr*" OR input="*chattr -ia .ssh*"
| stats count by src_ip | sort -count

-- Competing malware cleanup command (anti-competition behaviour)
index=honeypot sourcetype=cowrie eventid="cowrie.command.input"
  input="*pkill -9 secure.sh*" OR input="*hosts.deny*"
| stats count by src_ip | sort -count
```

---

## 11\. Kibana - Key Dashboard Queries

T-Pot's built-in Kibana dashboards are excellent for visual exploration. The most useful queries for digging beyond the defaults:

```
-- ECS-style field for source IP (T-Pot normalises to this)
src_ip: *

-- Filter to specific honeypot
type: "Cowrie"
type: "Dionaea"
type: "ADBHoney"
type: "Suricata"

-- Successful Cowrie logins only
type: "Cowrie" AND eventid: "cowrie.login.success"

-- Post-exploitation commands
type: "Cowrie" AND eventid: "cowrie.command.input"

-- EternalBlue/DoublePulsar alerts only
type: "Suricata" AND alert.signature: *DoublePulsar*

-- CVE-specific filter
type: "Suricata" AND alert.signature: *CVE-2024-4577*

-- Specific source IP investigation
src_ip: "81.9.145.130"

-- File downloads (malware delivery)
type: "Cowrie" AND eventid: "cowrie.session.file_download"
```

---

## 12\. Threat Intelligence Report

The full threat intelligence report generated from this deployment is available here:

**[T-Pot Threat Intelligence Report v2.0 (PDF)](reports/T-Pot_Threat_Intelligence_Report_v2.pdf)**

The report covers  includes:

-   Attack volume and geographic breakdown
-   Infrastructure classification of 100 attacking IPs via VirusTotal
-   Full CVE analysis across 12 Suricata-detected vulnerabilities
-   VirusTotal analysis of all 51 malware hashes (Cowrie, ADBHoney, Dionaea)
-   Reconstructed timelines for 5 confirmed attacker sessions
-   Attribution of coordinated campaigns (IONOS VPS fleet, mdrfckr SSH worm, Cobalt Strike JARM cluster)
-   Human-vs-automated attacker behaviour analysis
-   ICS/SCADA targeting findings (IEC-104 protocol against ConPot)
-   Full IOC table (IPs, hashes, SSH backdoor key, credentials, C2 domains)
-   MITRE ATT&CK technique mapping
-   Detection engineering recommendations

---

## 13\. Key Findings Summary

A few things that stood out from the data:

**The mdrfckr cryptomining worm is everywhere.** 14 separate IPs dropped the same mdrfckr SSH backdoor key across the observation period. This is a worm that's been active since at least 2019 and is still running. Its post-exploitation playbook (strip immutable flags, inject key, kill competing malware, check CPU resources) is fully scripted and highly consistent. If you have internet-facing SSH anywhere, check your `authorized_keys` files.

**WannaCry is still alive.** All 22 malware samples captured by Dionaea via EternalBlue were WannaCry variants - 88–95% detection rates on VirusTotal, most still contacting the original killswitch domain. In 2026. Nine years after the 2017 outbreak. Unpatched Windows SMBv1 nodes are still genuinely common on the internet.

**Someone knows ICS protocols.** IP `18.218.118.203` carries a Cobalt Strike JARM fingerprint AND probed ConPot with IEC 60870-5-104 (power grid SCADA protocol) across honeypot days. That combination of a red-team framework fingerprint on an IP that understands industrial control system protocols is worth flagging to ICS-CERT if you're operating in that space.

**Three malware samples don't exist on VirusTotal.** Hashes `7aa7aae3...`, `f7a2eec2...`, and `93d7393...` from Cowrie are genuinely absent. Original, uncatalogued samples sitting on the honeypot - which is exactly what honeypots are for.

**A human was in the box.** IP `40.112.183.29` (Azure) ran `w` and `top` manually across three separate sessions with 6–11 minute natural gaps between them. Every other IP in the dataset ran scripted playbooks at machine speed. This one was someone sitting at a keyboard.

---

## 14\. Repository Structure

```
tpot-threat-intelligence/
│
├── LICENSE
│
├── README.md                           
│
├── config/
│   ├── inputs.conf                    
│   ├── claude_desktop_config.json     
│
├── scripts/
│   ├── install-docker.sh   
│
├── report/
│   ├── T-Pot_Threat_Intelligence_Report_v2.md
│   ├── T-Pot_Threat_Intelligence_Report_v2.pdf
│
├── queries/
│   ├── queries.md
│
├── iocs/
│   ├──      
│
└── images/
```

---

## Notes

-   The T-Pot MCP connection used in log analysis was through Claude.ai - the Splunk and Virustotal MCP servers were connected as tools in the conversation.
-   All VirusTotal lookups were performed via MCP; the hash and IP results are documented in the full report.
-   Log retention was adjusted to ~3 months partway through the deployment. Some early-window tool detections (Masscan, Mozi, libredtail-http) are documented from pre-rotation logs and are no longer queryable in the current Splunk index.
-   This project feeds into a companion **SOC Detection Engineering lab** (separate repository) where captured IOCs and attack patterns are used to build and validate Splunk detection rules.
