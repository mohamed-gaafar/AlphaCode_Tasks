
# CodeAlpha_Network-Sniffer — Python Network Sniffer & Lightweight

CodeAlpha_NIDS is a minimal, extensible Network Intrusion Detection System (NIDS) built with Python and Scapy. It performs live packet capture, extracts key fields, runs simple heuristics to identify suspicious activity, and logs alerts for review.

Key Features
- Live packet capture from a selected interface (via Scapy)
- Extracts: source/destination IP, protocol (TCP/UDP/ICMP/DNS/HTTP), source/destination ports, TCP flags, and optional payload
- Detection rules: SYN scan, ICMP flood, repeated connection attempts (brute-force simulation), port scanning behavior, high-traffic source
- Console alerts and persistent alert logging to `alerts.log`
- Optional periodic console visualization of top talkers and protocol distribution

Quick Requirements
- Python 3.8+
- Install dependencies from `requirements.txt` (Scapy is required)
- Windows users: run as Administrator and install Npcap (https://nmap.org/npcap/) for live capture

Install

```bash
pip install -r requirements.txt
```

Usage

Run the sniffer (requires elevated privileges for live capture):

```bash
python sniffer.py -i "<Interface Name>" --visual
```

- `-i/--iface`: optional interface name; omit to use Scapy's default.
- `--visual`: enable periodic console summaries of top talkers and protocol distribution.

Configuration and Tuning
- Thresholds and detection windows are defined in `Analyzer` (in `sniffer.py`). Tweak the following values to match network scale and baseline traffic:
	- `syn_scan_threshold_unique_ports` (default 10)
	- `syn_scan_window` (seconds)
	- `icmp_flood_threshold`
	- `high_traffic_threshold`
	- `repeated_conn_threshold`
	- `dns_unique_threshold`

Testing (local simulation)
- A quick unit-style simulation was used during development: the `Analyzer` class can be exercised directly (no live capture) by injecting synthesized packet info dicts. This lets you validate detection logic without admin privileges.

Output & Logs
- Alerts print to the console and are appended to `alerts.log` in the repository root. Each alert contains a timestamp, source IP, destination IP, threat type, and severity level.

Contributing
- Contributions welcome. Create issues and pull requests on the GitHub repo.

License
- This project is provided under the MIT license (see `LICENSE`).

Security & Privacy
- This tool inspects packet metadata and optionally payloads. Use responsibly on networks you own or are authorized to monitor. Do not capture or store sensitive payloads unless necessary and permitted.

Next Steps
- Tune detection thresholds to your environment
- Add more signatures (DNS heuristics, HTTP anomaly detection)
- Add optional JSON output mode or integration with SIEM systems

See `sniffer.py` for implementation details and threshold defaults.


