#!/usr/bin/env python3
"""
Fetches fail2ban status + auth attack data and writes a JSON file
for the dashboard container to read.
Run via cron every 30 seconds: * * * * * /usr/bin/python3 /opt/fail2ban-dashboard/fetch-status.py
"""
import subprocess
import json
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict

OUTPUT_FILE = "/var/lib/fail2ban-dashboard/f2b-status.json"
AUTH_LOG = "/var/log/auth.log"
F2B_DB = "/var/lib/fail2ban/fail2ban.sqlite3"


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout
    except Exception:
        return ""


def get_banned_ips():
    """Return list of dicts with IP + ban metadata for countdown support."""
    output = run(["fail2ban-client", "status", "sshd"])
    raw_ips = []
    for line in output.split("\n"):
        if "Banned IP list" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                raw_ips = [ip for ip in parts[-1].strip().split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)]
                break

    # Enrich with ban metadata from ban history
    ban_map = {}
    for b in get_ban_history():
        if b["jail"] == "sshd" and b["ip"] not in ban_map:
            ban_map[b["ip"]] = b

    enriched = []
    for ip in raw_ips:
        info = {"ip": ip, "ban_time": None, "bantime": None}
        if ip in ban_map:
            info["ban_time"] = ban_map[ip]["time"]
            info["bantime"] = ban_map[ip]["bantime"]
        enriched.append(info)
    return enriched


def get_jail_stats():
    output = run(["fail2ban-client", "status", "sshd"])
    stats = {}
    for line in output.split("\n"):
        m = re.search(r"Currently failed:\s*(\d+)", line)
        if m: stats["currently_failed"] = int(m.group(1))
        m = re.search(r"Total failed:\s*(\d+)", line)
        if m: stats["total_failed"] = int(m.group(1))
        m = re.search(r"Currently banned:\s*(\d+)", line)
        if m: stats["currently_banned"] = int(m.group(1))
        m = re.search(r"Total banned:\s*(\d+)", line)
        if m: stats["total_banned"] = int(m.group(1))
    return stats


def parse_auth_log():
    """Parse /var/log/auth.log for failed SSH login attempts."""
    ip_counts = defaultdict(int)
    user_counts = defaultdict(int)
    attacks = []
    timeline = defaultdict(int)

    failed_re = re.compile(
        r"(\d{4}-\d{2}-\d{2}T[\d:.]+)\+\d+:\d+\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)"
    )
    invalid_re = re.compile(
        r"(\d{4}-\d{2}-\d{2}T[\d:.]+)\+\d+:\d+\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)"
    )

    try:
        seen = set()
        with open(AUTH_LOG, "r") as f:
            for line in f:
                m = failed_re.search(line)
                if not m:
                    m = invalid_re.search(line)
                if not m:
                    continue
                ts_str, username, ip = m.group(1), m.group(2), m.group(3)
                key = f"{ts_str}:{ip}:{username}"
                if key in seen:
                    continue
                seen.add(key)
                try:
                    ts = datetime.fromisoformat(ts_str)
                except Exception:
                    continue

                attacks.append({
                    "time": ts.strftime("%Y-%m-%d %H:%M"),
                    "timestamp_iso": ts.isoformat(),
                    "user": username,
                    "ip": ip
                })
                ip_counts[ip] += 1
                user_counts[username] += 1
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                timeline[hour_key] += 1
    except Exception as e:
        print(f"Error parsing auth.log: {e}")

    ip_counts = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
    user_counts = dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True))
    timeline = dict(sorted(timeline.items()))

    return {
        "attacks": attacks[-200:],
        "ip_counts": dict(list(ip_counts.items())[:30]),
        "user_counts": dict(list(user_counts.items())[:20]),
        "timeline": timeline,
        "total_attempts": sum(ip_counts.values()),
    }


def get_ban_history():
    """Read ban history from fail2ban's SQLite database."""
    bans = []
    try:
        db_output = run([
            "sqlite3", F2B_DB,
            "SELECT jail, ip, datetime(timeofban, 'unixepoch', 'localtime'), bantime, bancount FROM bans ORDER BY timeofban DESC;"
        ])
        for line in db_output.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) == 5:
                    bans.append({
                        "jail": parts[0],
                        "ip": parts[1],
                        "time": parts[2],
                        "bantime": int(parts[3]),
                        "bancount": int(parts[4]),
                    })
    except Exception:
        pass
    return bans


def compute_stats(auth_data, ban_history, now):
    """Compute enriched statistics for the dashboard."""
    attacks = auth_data["attacks"]

    # Attack rate (attempts per hour, last 24h)
    one_hour_ago = now - timedelta(hours=1)
    one_day_ago = now - timedelta(days=1)
    recent_1h = sum(1 for a in attacks if datetime.fromisoformat(a["timestamp_iso"]) > one_hour_ago)
    recent_24h = sum(1 for a in attacks if datetime.fromisoformat(a["timestamp_iso"]) > one_day_ago)

    # First and last attack times
    first_attack = None
    last_attack = None
    if attacks:
        attack_times = [datetime.fromisoformat(a["timestamp_iso"]) for a in attacks]
        first_attack = min(attack_times).isoformat()
        last_attack = max(attack_times).isoformat()

    # Peak attack hour
    peak_hour = None
    peak_count = 0
    for hour, count in auth_data["timeline"].items():
        if count > peak_count:
            peak_count = count
            peak_hour = hour

    # Unique IPs seen in last 24h
    recent_ips = set()
    for a in attacks:
        if datetime.fromisoformat(a["timestamp_iso"]) > one_day_ago:
            recent_ips.add(a["ip"])

    # Ban history enrichment — compute ban duration in human format, relative time
    enriched_bans = []
    for ban in ban_history:
        try:
            ban_dt = datetime.strptime(ban["time"], "%Y-%m-%d %H:%M:%S")
            delta = now - ban_dt
            enriched_bans.append({
                **ban,
                "time_relative": humanize_delta(delta),
                "bantime_human": humanize_duration(ban["bantime"]),
                "time_iso": ban_dt.isoformat(),
            })
        except Exception:
            enriched_bans.append({
                **ban,
                "time_relative": ban["time"],
                "bantime_human": humanize_duration(ban["bantime"]),
                "time_iso": ban["time"],
            })

    # Attack enrichment — relative times
    enriched_attacks = []
    for a in attacks:
        try:
            a_dt = datetime.fromisoformat(a["timestamp_iso"])
            delta = now - a_dt
            enriched_attacks.append({
                **a,
                "time_relative": humanize_delta(delta),
            })
        except Exception:
            enriched_attacks.append({
                **a,
                "time_relative": a["time"],
            })

    # Currently banned IPs enrichment with ban info
    banned_ip_set = set(b["ip"] for b in ban_history if b["jail"] == "sshd")
    # Get ban time for each currently banned IP (most recent ban)
    ban_map = {}
    for b in ban_history:
        if b["ip"] not in ban_map:
            ban_map[b["ip"]] = b

    return {
        "attacks_per_hour": recent_1h,
        "attacks_per_24h": recent_24h,
        "unique_ips_24h": len(recent_ips),
        "first_attack": first_attack,
        "last_attack": last_attack,
        "peak_hour": peak_hour,
        "peak_count": peak_count,
        "enriched_bans": enriched_bans,
        "enriched_attacks": enriched_attacks,
        "ban_map": ban_map,
    }


def humanize_delta(delta):
    """Convert a timedelta to a human-readable relative time string."""
    seconds = int(delta.total_seconds())
    if seconds < 0:
        seconds = abs(seconds)
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days < 7:
        return f"{days}d ago"
    weeks = days // 7
    return f"{weeks}w ago"


def humanize_duration(seconds):
    """Convert seconds to a human-readable duration."""
    if seconds < 0:
        return "permanent"
    if seconds >= 86400 * 365:
        return "permanent"
    if seconds >= 86400:
        d = seconds // 86400
        rem = seconds % 86400
        h = rem // 3600
        if h:
            return f"{d}d {h}h"
        return f"{d}d"
    if seconds >= 3600:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        if m:
            return f"{h}h {m}m"
        return f"{h}h"
    if seconds >= 60:
        m = seconds // 60
        return f"{m}m"
    return f"{seconds}s"


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    now = datetime.now()
    banned_ips = get_banned_ips()
    jail_stats = get_jail_stats()
    auth_data = parse_auth_log()
    ban_history = get_ban_history()
    enriched = compute_stats(auth_data, ban_history, now)

    data = {
        "timestamp": now.isoformat(),
        "banned_ips": [b["ip"] for b in banned_ips],
        "banned_ips_enriched": banned_ips,
        "jail_stats": jail_stats,
        "auth_data": auth_data,
        "ban_history": ban_history,
        "enriched": enriched,
        "now_iso": now.isoformat(),
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f)

    print(f"Updated {OUTPUT_FILE} — {len(banned_ips)} banned IPs, "
          f"{auth_data['total_attempts']} total attacks, "
          f"{len(ban_history)} ban records")