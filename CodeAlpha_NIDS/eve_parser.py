#!/usr/bin/env python3
"""
Suricata EVE JSON Log Parser and Visualizer
This script parses Suricata's eve.json log file and generates basic visualizations.
"""

import json
import sys
from collections import Counter
import matplotlib.pyplot as plt

def parse_eve_log(log_file):
    """Parse the EVE JSON log file and extract alerts."""
    alerts = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Log file {log_file} not found.")
        return []

    return alerts

def visualize_alerts(alerts):
    """Generate visualizations from alert data."""
    if not alerts:
        print("No alerts found in the log file.")
        return

    # Count alerts by signature
    signatures = [alert['alert']['signature'] for alert in alerts]
    sig_counts = Counter(signatures)

    # Plot top 10 signatures
    top_sigs = dict(sig_counts.most_common(10))
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(top_sigs)), list(top_sigs.values()), align='center')
    plt.xticks(range(len(top_sigs)), list(top_sigs.keys()), rotation=45, ha='right')
    plt.title('Top 10 Alert Signatures')
    plt.xlabel('Signature')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

    # Count alerts by source IP
    src_ips = [alert.get('src_ip', 'Unknown') for alert in alerts]
    ip_counts = Counter(src_ips)

    # Plot top 10 source IPs
    top_ips = dict(ip_counts.most_common(10))
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(top_ips)), list(top_ips.values()), align='center')
    plt.xticks(range(len(top_ips)), list(top_ips.keys()), rotation=45, ha='right')
    plt.title('Top 10 Source IPs Generating Alerts')
    plt.xlabel('Source IP')
    plt.ylabel('Alert Count')
    plt.tight_layout()
    plt.show()

def main():
    if len(sys.argv) != 2:
        print("Usage: python eve_parser.py <eve.json>")
        sys.exit(1)

    log_file = sys.argv[1]
    alerts = parse_eve_log(log_file)
    print(f"Parsed {len(alerts)} alerts from {log_file}")
    visualize_alerts(alerts)

if __name__ == "__main__":
    main()