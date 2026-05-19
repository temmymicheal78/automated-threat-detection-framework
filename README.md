# Automated Threat Detection & Response Framework

A real-time intrusion prevention framework that detects SSH brute-force attacks and automatically blocks them at the network firewall by combining behavioural log analysis with multi-source threat intelligence.

##MSc Cybersecurity Dissertation Project — London Metropolitan University (2025–2026)##


Key Results

| Metric | Result |
|---|---|
| **Detection rate** | 100% across Hydra, Medusa, and Ncrack (20 trials) |
| **Mean response time** | 9.8 seconds (σ = 0.6s) |
| **False positives** | 0 against curated benign IP whitelist |
| **Unit tests passing** | 110/110 |

---

##  Architecture

A five-VM laboratory simulating an enterprise network:
Kali Attacker] → [Gateway] → [Firewall (iptables)] → [Endpoint]
↕
[Detector VM]
(via SSH/paramiko)



Detection and enforcement are deliberately separated across two machines, following the least-privilege principle.

---

## Technical Stack

- **Language:** Python 3.12
- **SSH:** paramiko
- **HTTP:** requests
- **Persistence:** sqlite3
- **Testing:** pytest
- **Firewall:** iptables (Ubuntu 24.04)
- **Threat Intelligence:** AbuseIPDB, VirusTotal, AlienVault OTX
- **Geolocation:** ip-api.com
- **Lab Environment:** Oracle VirtualBox

## Features

- **Sliding-window detection** (5 attempts / 300 seconds, configurable)
- **Multi-source threat intelligence aggregation** with parallel API queries
- **Dual-threshold decision engine** producing BLOCK / MONITOR / IGNORE verdicts
- **Geolocation enrichment** (country, city, ASN, ISP)
- **Persistent SQLite audit trail** surviving system restarts
- **Fail-safe behaviour** when threat intel APIs are unavailable
- **Network-level enforcement** at the firewall's FORWARD chain

---

## How the Pipeline Works

1. **Log Capture** — `iptables LOG` rule on the firewall records every SSH packet
2. **Log Streaming** — Detector tails the kernel log over an authenticated SSH channel
3. **Parsing** — Regex extracts timestamp, source IP, destination port
4. **Detection** — Per-IP sliding window (deque) triggers on 5 fails in 300 seconds
5. **Threat Intelligence** — Parallel queries to AbuseIPDB, VirusTotal, OTX + geolocation
6. **Decision** — Dual-threshold rule (behavioural AND reputational evidence required)
7. **Enforcement** — `iptables DROP` rule pushed to the firewall via SSH
8. **Persistence** — All events, assessments, and blocks logged to SQLite

---

## Project Structure

src/
├── api_client.py      # AbuseIPDB HTTP client
├── config.py          # Configuration loader
├── database.py        # SQLite persistence
├── decision.py        # Dual-threshold decision engine
├── detector.py        # Sliding-window algorithm
├── firewall.py        # iptables push via paramiko
├── log_parser.py      # Regex-based log parsing
├── main.py            # CLI orchestrator
├── multi_intel.py     # Parallel threat intel aggregator
├── notifier.py        # Email alerts on BLOCK
├── reporter.py        # CSV report generation
└── threat_intel.py    # Threat intelligence data structures



---

##  Setup (Brief)

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your API keys:
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
OTX_API_KEY=your_key_here


4. Edit `config.json` to point to your firewall and threshold values
5. Run: `python3 src/main.py --live --firewall-mode ips`

---

##  Acknowledgements

This project builds on the following open-source libraries:
- paramiko, requests, python-dateutil, pytest

Threat intelligence is provided by:
- AbuseIPDB (community-driven IP reputation)
- VirusTotal (multi-vendor aggregation)
- AlienVault Open Threat Exchange
- ip-api.com (geolocation)

---

##  Methodology

The architectural and methodological choices in this project are informed by:
- Inayat et al. (2016) — automated intrusion response systems
- Tounsi & Rais (2018) — threat intelligence classification
- Bryant & Saiedian (2017) — network-level enforcement design
- Bace & Mell (NIST SP 800-31) — IDS principles
- Sommer & Paxson (2010) — the false-positive challenge

Full citations available in the project dissertation.

---

##  Disclaimer

This framework was built for educational and defensive cybersecurity research. It was developed and tested entirely within an isolated VirtualBox laboratory. The tool is designed to **protect networks, not attack them**. Users are responsible for compliance with applicable laws including the UK Computer Misuse Act 1990 and GDPR.

---

##  Author

**Temiloluwa Micheal Ogunrinde**  
MSc Networking and Cybersecurity  
London Metropolitan University · 2025–2026

temmymicheal78@gmail.com

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.



