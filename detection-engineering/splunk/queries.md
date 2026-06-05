## Successful Login After Bruteforce

```bash
index=honeypot sourcetype="cowrie" 
(eventid="cowrie.login.failed"
 OR eventid="cowrie.login.success"
 OR eventid="cowrie.command.input"
 OR eventid="cowrie.session.file_download")
| stats
    count(eval(eventid="cowrie.login.failed")) as failed_attempts
    count(eval(eventid="cowrie.login.success")) as successful_logins
    values(username) as usernames
    values(password) as passwords
    values(input) as commands
    values(shasum) as downloaded_file
    by src_ip, host
| where failed_attempts >= 8 AND successful_logins > 0

```



## Elasticsearch Ransom Note Attempt

```bash
index="honeypot" sourcetype="suricata:json"
dest_port=9200
(payload_printable="*/read_me/_doc*"
 OR payload_printable="*database has been deleted*")
| rex field=payload_printable "(?<btc_wallet>bc1[a-zA-Z0-9]+)"
| rex field=payload_printable "(?<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
| stats
    count
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(dest_ip) as target_ip
    values(btc_wallet) as bitcoin_wallet
    values(email) as contact_email
    values(payload_printable) as evidence
    by src_ip, host
| convert ctime(first_seen) ctime(last_seen)
| eval severity="high"
| eval attack_type="Elasticsearch Ransom Note Attempt"

```

