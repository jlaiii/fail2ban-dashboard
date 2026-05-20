# Fail2Ban Dashboard

A modern, real-time web dashboard for [Fail2Ban](https://www.fail2ban.org/) -- monitor SSH intrusion attempts, track banned IPs, and investigate attackers with built-in IP intelligence.

**Live Demo:** [https://jlaiii.github.io/fail2ban-dashboard/](https://jlaiii.github.io/fail2ban-dashboard/)

---

## Features

- **Real-time monitoring** -- Auto-refreshes every 30 seconds via JS polling (no full page reload)
- **Currently banned IPs** with live ban countdown timers showing time until unbanned
- **IP intelligence modal** -- Click any IP for geo-location, ISP/org, threat classification (GreyNoise), local attack data, and external lookup links (AbuseIPDB, VirusTotal, Shodan, Censys)
- **Country flags** inline next to all IP addresses via batch geo-lookup with server-side caching
- **Ban history** with relative timestamps and ban duration tags
- **Top attacker IPs** and **top targeted usernames** with visual bar charts
- **Attack timeline** -- hourly histogram showing attack patterns
- **Search / filter bar** -- filter across all sections by IP, username, or timestamp
- **Dark / light theme toggle** -- persists via localStorage, full CSS variable swap
- **Docker deployment** -- single container, minimal config

---

## Screenshots

The dashboard features a dark glassmorphism design with accent-colored stat cards, flag icons, and live countdowns:

- Stat cards showing banned IPs, attacks/hr, attacks/24h, total bans, unique IPs, peak hour
- Banned IPs table with red status dots, country flags, and countdown timers
- Ban history with color-coded duration tags
- Top attackers bar chart
- Attack timeline histogram

---

## Quick Start

### Docker (Recommended)

```bash
# Clone the repo
git clone https://github.com/jlaiii/fail2ban-dashboard.git
cd fail2ban-dashboard

# Build and run
docker compose build
docker compose up -d
```

The dashboard will be available at `http://localhost:8080`.

### Manual Setup

```bash
# Install dependencies
pip install flask

# Set up the data fetcher as a cron job (runs every minute)
crontab -e
# Add: * * * * * python3 /path/to/fail2ban-dashboard/fetch-status.py

# Run the Flask app
cd app
python dashboard.py
```

---

## Architecture

```
fail2ban-dashboard/
  fetch-status.py       # Cron script: reads fail2ban logs, writes JSON
  docker-compose.yml    # Docker Compose config
  app/
    dashboard.py        # Flask app: serves dashboard + API endpoints
    Dockerfile          # Container build (Python 3.12 Alpine)
    requirements.txt    # Flask dependency
    templates/
      dashboard.html    # Single-page dashboard (all 5 features)
```

### Data Flow

1. `fetch-status.py` runs every minute via cron
2. Reads Fail2Ban jail status, auth logs, and ban history
3. Writes `/var/lib/fail2ban-dashboard/f2b-status.json`
4. Flask app reads the JSON file and serves the dashboard
5. Browser polls `/api/status` every 30 seconds for live updates

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/api/status` | GET | Full status JSON |
| `/api/ip/<ip>` | GET | IP intelligence (geo + threat + local data) |
| `/api/geo/batch` | POST | Batch geo-lookup for country flags |

---

## Configuration

### Docker Run (Alternative to Compose)

```bash
docker run -d \
  --name f2b-dashboard \
  --network host \
  -v /var/lib/fail2ban-dashboard/f2b-status.json:/host_data/f2b-status.json:ro \
  fail2ban-dashboard-dashboard
```

### Custom Data Path

Edit `fetch-status.py` to change `OUTPUT_FILE` if you want the JSON written elsewhere.

### Fail2Ban Integration

The fetch script reads from:
- `fail2ban-client status sshd` -- current banned IPs and jail stats
- `/var/log/auth.log` -- authentication attempts and failures
- Fail2Ban ban database -- ban history with timestamps and durations

Ensure Fail2Ban is installed and the `sshd` jail is active:

```bash
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
fail2ban-client status sshd
```

---

## Tech Stack

- **Backend:** Python 3.12, Flask
- **Frontend:** Vanilla JS, CSS custom properties (no frameworks)
- **Data:** Fail2Ban CLI + auth log parsing
- **Geo-IP:** ipapi.co / ip-api.com (free tier, server-side cached)
- **Threat Intel:** GreyNoise Community API (free)
- **Container:** Alpine Linux, Docker
- **Fonts:** Inter via Google Fonts
- **Flags:** flagcdn.com

---

## License

MIT

---

## Demo

Check out the interactive demo: [https://jlaiii.github.io/fail2ban-dashboard/](https://jlaiii.github.io/fail2ban-dashboard/)