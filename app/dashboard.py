from flask import Flask, render_template, jsonify, request
import json
import os
import urllib.request
import urllib.error
import time
import threading
from datetime import datetime
from collections import OrderedDict

app = Flask(__name__)

STATUS_FILE = "/host_data/f2b-status.json"

# In-memory geo cache: ip -> {data, cached_at}
_geo_cache = {}
_geo_cache_lock = threading.Lock()
GEO_CACHE_TTL = 86400  # 24 hours


def get_status():
    try:
        with open(STATUS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "timestamp": datetime.now().isoformat(),
            "banned_ips": [],
            "banned_ips_enriched": [],
            "jail_stats": {},
            "auth_data": {"attacks": [], "ip_counts": {}, "user_counts": {}, "timeline": {}, "total_attempts": 0},
            "ban_history": [],
            "enriched": {},
            "now_iso": datetime.now().isoformat(),
        }


# IP enrichment API proxies -- fallback chain
GEO_APIS = [
    {
        "name": "ipapi.co",
        "url": "https://ipapi.co/{ip}/json/",
        "timeout": 5,
        "map": lambda d: {
            "ip": d.get("ip", ""),
            "country": d.get("country_name", d.get("country_code", "")),
            "country_code": d.get("country_code", ""),
            "region": d.get("region", ""),
            "city": d.get("city", ""),
            "postal": d.get("postal", ""),
            "latitude": d.get("latitude"),
            "longitude": d.get("longitude"),
            "timezone": d.get("timezone", ""),
            "utc_offset": d.get("utc_offset", ""),
            "isp": d.get("org", ""),
            "org": d.get("org", ""),
            "asn": d.get("asn", ""),
            "network": d.get("network", ""),
            "continent": d.get("continent_code", ""),
            "in_eu": d.get("in_eu"),
            "currency": d.get("currency", ""),
            "calling_code": d.get("country_calling_code", ""),
            "languages": d.get("languages", ""),
            "source": "ipapi.co",
        },
    },
    {
        "name": "ip-api.com",
        "url": "http://ip-api.com/json/{ip}",
        "timeout": 5,
        "map": lambda d: {
            "ip": d.get("query", ""),
            "country": d.get("country", ""),
            "country_code": d.get("countryCode", ""),
            "region": d.get("regionName", ""),
            "city": d.get("city", ""),
            "postal": d.get("zip", ""),
            "latitude": d.get("lat"),
            "longitude": d.get("lon"),
            "timezone": d.get("timezone", ""),
            "utc_offset": "",
            "isp": d.get("isp", ""),
            "org": d.get("org", ""),
            "asn": d.get("as", ""),
            "network": "",
            "continent": "",
            "in_eu": None,
            "currency": "",
            "calling_code": "",
            "languages": "",
            "source": "ip-api.com",
        },
    },
]

THREAT_APIS = [
    {
        "name": "GreyNoise",
        "url": "https://api.greynoise.io/v3/community/{ip}",
        "timeout": 5,
        "map": lambda d: {
            "classification": d.get("classification", "unknown"),
            "noise": d.get("noise", False),
            "riot": d.get("riot", False),
            "message": d.get("message", ""),
            "link": d.get("link", ""),
            "source": "GreyNoise",
        },
    },
]


def fetch_json(url, timeout=5):
    """Fetch JSON from a URL, return parsed dict or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "F2B-Dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _lookup_geo_single(ip):
    """Look up geo for a single IP, using cache. Returns minimal dict {country_code, country} or None."""
    with _geo_cache_lock:
        if ip in _geo_cache:
            entry = _geo_cache[ip]
            if time.time() - entry["cached_at"] < GEO_CACHE_TTL:
                return entry["data"]
            # expired, remove
            del _geo_cache[ip]

    # Try each API
    for api in GEO_APIS:
        url = api["url"].format(ip=ip)
        raw = fetch_json(url, timeout=api["timeout"])
        if raw and (raw.get("status") != "fail"):
            mapped = api["map"](raw)
            if mapped.get("country_code"):
                result = {
                    "country_code": mapped["country_code"],
                    "country": mapped.get("country", ""),
                }
                with _geo_cache_lock:
                    _geo_cache[ip] = {"data": result, "cached_at": time.time()}
                return result
    return None


@app.route("/")
def index():
    data = get_status()
    enriched = data.get("enriched", {})

    now = datetime.now()
    try:
        data_time = datetime.fromisoformat(data["timestamp"])
        data_age_seconds = int((now - data_time).total_seconds())
        if data_age_seconds < 60:
            data_age = f"{data_age_seconds}s ago"
        elif data_age_seconds < 3600:
            data_age = f"{data_age_seconds // 60}m ago"
        else:
            data_age = f"{data_age_seconds // 3600}h ago"
    except Exception:
        data_age = "unknown"

    return render_template("dashboard.html",
        banned_ips=data["banned_ips"],
        banned_ips_enriched=data.get("banned_ips_enriched", []),
        jail_stats=data.get("jail_stats", {}),
        auth_data=data.get("auth_data", {}),
        ban_history=data.get("ban_history", []),
        enriched=enriched,
        last_updated=data.get("timestamp", ""),
        data_age=data_age,
        now_str=now.strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/api/ip/<ip>")
def ip_lookup(ip):
    """Proxy endpoint for IP enrichment with fallback chain."""
    result = {"ip": ip, "geo": None, "threat": None, "errors": []}

    # Geo fallback chain
    for api in GEO_APIS:
        url = api["url"].format(ip=ip)
        raw = fetch_json(url, timeout=api["timeout"])
        if raw and (raw.get("status") != "fail"):
            mapped = api["map"](raw)
            if mapped.get("country") or mapped.get("city"):
                result["geo"] = mapped
                break
        else:
            result["errors"].append(f"{api['name']}: no response or failed")

    # Threat lookup (best-effort, don't fail if down)
    for api in THREAT_APIS:
        url = api["url"].format(ip=ip)
        raw = fetch_json(url, timeout=api["timeout"])
        if raw:
            mapped = api["map"](raw)
            result["threat"] = mapped
            break
        else:
            result["errors"].append(f"{api['name']}: no response")

    # Compute local attack data for this IP from the status file
    data = get_status()
    auth_data = data.get("auth_data", {})
    ip_attack_count = auth_data.get("ip_counts", {}).get(ip, 0)
    ip_usernames = []
    for attack in auth_data.get("attacks", []):
        if attack.get("ip") == ip:
            u = attack.get("user", "")
            if u and u not in ip_usernames:
                ip_usernames.append(u)
    is_banned = ip in data.get("banned_ips", [])
    ban_info = None
    for b in data.get("ban_history", []):
        if b.get("ip") == ip:
            ban_info = b
            break

    result["local"] = {
        "attack_count": ip_attack_count,
        "usernames_tried": ip_usernames[:10],
        "currently_banned": is_banned,
        "ban_info": ban_info,
    }

    return jsonify(result)


@app.route("/api/status")
def api_status():
    return jsonify(get_status())


@app.route("/api/geo/batch", methods=["POST"])
def geo_batch():
    """Batch geo lookup for a list of IPs. Uses in-memory cache.
    Expects JSON body: {"ips": ["1.2.3.4", ...]}
    Returns: {"1.2.3.4": {"country_code": "US", "country": "United States"}, ...}
    """
    body = request.get_json(silent=True) or {}
    ips = body.get("ips", [])
    # Deduplicate and limit
    ips = list(dict.fromkeys(ips))[:100]
    result = {}
    for ip in ips:
        geo = _lookup_geo_single(ip)
        if geo:
            result[ip] = geo
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)