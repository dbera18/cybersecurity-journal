#!/usr/bin/env python3
"""
detect_failed_logins.py - flag possible SSH brute-force sources in an auth log.

Usage:
    python3 detect_failed_logins.py auth.log
    python3 detect_failed_logins.py auth.log --threshold 3 --out report.csv
"""

import argparse
import csv
import re
import sys
from collections import defaultdict

# Matches lines like:
#   Nov 16 08:03:45 labvm sshd[1210]: Failed password for root from 203.0.113.45 port 41022 ssh2
#   Nov 16 08:03:51 labvm sshd[1211]: Failed password for invalid user admin from 203.0.113.45 port 41030 ssh2
FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+)\s+"
    r"from (?P<ip>[\d.]+) port \d+"
)


def parse_log(path):
    """Return a list of dicts, one per failed login attempt."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                events.append({
                    "timestamp": m.group("timestamp"),
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "invalid_user": bool(m.group("invalid")),
                })
    return events


def summarize(events):
    """Group failed attempts by source IP."""
    by_ip = defaultdict(lambda: {"count": 0, "users": set(), "first": None, "last": None})
    for e in events:
        s = by_ip[e["ip"]]
        s["count"] += 1
        s["users"].add(e["user"])
        s["first"] = s["first"] or e["timestamp"]
        s["last"] = e["timestamp"]
    return by_ip


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in an auth log.")
    parser.add_argument("logfile", help="path to auth.log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts per IP before flagging (default: 5)")
    parser.add_argument("--out", default="report.csv", help="CSV output path (default: report.csv)")
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {args.logfile}")

    summary = summarize(events)
    rows = sorted(summary.items(), key=lambda kv: kv[1]["count"], reverse=True)

    print(f"[*] Parsed {len(events)} failed SSH login attempts from {len(summary)} IPs")
    print(f"[*] Alert threshold: {args.threshold} failures\n")
    print(f"{'SOURCE IP':<16} {'FAILS':>5}  {'USERS':>5}  {'FIRST SEEN':<16} {'LAST SEEN':<16} STATUS")
    print("-" * 80)

    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["source_ip", "failed_attempts", "unique_users", "usernames",
                         "first_seen", "last_seen", "status"])
        for ip, s in rows:
            status = "ALERT: possible brute force" if s["count"] >= args.threshold else "ok"
            print(f"{ip:<16} {s['count']:>5}  {len(s['users']):>5}  "
                  f"{s['first']:<16} {s['last']:<16} {status}")
            writer.writerow([ip, s["count"], len(s["users"]), ";".join(sorted(s["users"])),
                             s["first"], s["last"], status])

    alerts = sum(1 for _, s in rows if s["count"] >= args.threshold)
    print(f"\n[+] {alerts} IP(s) flagged. Report written to {args.out}")


if __name__ == "__main__":
    main()
