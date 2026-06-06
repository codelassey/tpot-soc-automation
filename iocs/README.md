# IOC Files

Indicators of Compromise extracted from T-Pot honeypot data.

## Files

| File | Contents | I will use in |
|------|----------|---------------|
| `ip-blocklist.txt` | 172 IPs + 3 CIDRs (clean, one per line) | OPNsense URL Table Alias for Firewall Rule |
| `dns-blocklist.txt` | 3 domains to sinkhole | OPNsense Unbound DNS |
| `c2-urls.txt` | 7 active payload delivery URLs | Suricata |
| `malicious-sha256.txt` | 25 malicious SHA256 hashes | EDR / SIEM |
| `malicious-md5-hashes-wannacry.txt` | 21 WannaCry MD5 variants | EDR / AV / SIEM |
| `undetected-hashes.txt` | 3 hashes not in VirusTotal | Submit to MalwareBazaar |
| `mdrfckr-ssh-backdoor-key.txt` | MDRFCKR SSH backdoor RSA public key + detection command | Linux SSH persistence audit (`authorized_keys`) |



## OPNsense Alias Setup

(Will add the setup to the main repo)


1.  Host `ip-blocklist.txt` on an internal HTTP server

2.  **Firewall > Aliases > Add**

-   Type: `URL Table (IPs)`

-   URL: `http://my-ip/ip-blocklist.txt`



## Critical Warning - DO NOT Block These Domains



```

iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com  < WannaCry killswitch

iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com  < WannaCry killswitch variant

acroipm.adobe.com                              < Legitimate Adobe domain (abused)

acroipm2.adobe.com                             < Legitimate Adobe domain (abused)

```



Blocking the killswitch domains **reactivates WannaCry encryption** on infected hosts. Monitor for DNS queries to these domains instead so that any query found equals an infected host.



## mdrfckr Backdoor Key Audit



Run this on every Linux host in your environment:



```bash
grep -r "mdrfckr" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```



Any output = compromised host. Rotate all SSH keys and rebuild.

