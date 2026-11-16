# Day 01: SSH Failed-Login Detector

A small Python tool that parses a Linux `auth.log`, counts failed SSH password attempts per source IP, and flags likely brute-force sources.

## What it does
- Uses a regex to extract **timestamp, username and source IP** from every `Failed password` line (including `invalid user` attempts)
- Groups attempts by IP and tracks how many distinct usernames each IP tried
- Flags any IP at or above a configurable threshold (default: 5)
- Prints a summary table and writes `report.csv`

## Usage
```bash
python3 detect_failed_logins.py auth.log
python3 detect_failed_logins.py auth.log --threshold 3 --out report.csv
```

## Sample output
```
[*] Parsed 23 failed SSH login attempts from 5 IPs
[*] Alert threshold: 5 failures

SOURCE IP        FAILS  USERS  FIRST SEEN       LAST SEEN        STATUS
--------------------------------------------------------------------------------
198.51.100.7         9      5  Nov 16 08:22:41  Nov 16 08:22:57  ALERT: possible brute force
203.0.113.45         7      4  Nov 16 08:03:45  Nov 16 08:04:03  ALERT: possible brute force
192.0.2.88           4      2  Nov 16 09:05:02  Nov 16 09:05:23  ok
10.0.0.15            2      1  Nov 16 08:41:18  Nov 16 08:41:25  ok
192.168.56.20        1      1  Nov 16 08:15:09  Nov 16 08:15:09  ok

[+] 2 IP(s) flagged. Report written to report.csv
```

## Analysis
- **198.51.100.7** tried 5 different common service usernames (`ubuntu`, `pi`, `git`, `postgres`, `root`) in 16 seconds: classic automated credential guessing.
- **203.0.113.45** hammered `root` plus default accounts (`admin`, `test`, `oracle`) within 18 seconds.
- **10.0.0.15** and **192.168.56.20** each failed a couple of times and then logged in successfully: almost certainly a mistyped password, not an attack.
- **192.0.2.88** stayed under the threshold. Low-and-slow attackers do this on purpose, which is why a time-window rule would be a good next step.

## MITRE ATT&CK mapping
**T1110 – Brute Force** (sub-techniques T1110.001 Password Guessing and T1110.003 Password Spraying). Many usernames from one IP in a short window points to guessing or spraying.

## Defenses this supports
- Feed flagged IPs into `fail2ban` or a firewall blocklist
- Disable SSH password auth (`PasswordAuthentication no`) and use keys
- Disable direct root login (`PermitRootLogin no`)

## Ideas for later
- Alert on N failures **within a time window**, not just total
- Flag a successful login that follows many failures from the same IP (possible compromise)
- Write the same logic as a Sigma rule

## Note
`auth.log` here is synthetic sample data using documentation-reserved IP ranges (RFC 5737). No real systems were involved.
