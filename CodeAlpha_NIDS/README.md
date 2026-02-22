# Suricata Network Intrusion Detection System (NIDS) Setup

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)

A comprehensive setup guide and configuration for deploying Suricata as a Network Intrusion Detection System (NIDS) with custom detection rules, monitoring capabilities, and visualization tools.

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Custom Detection Rules](#custom-detection-rules)
- [Running Suricata](#running-suricata)
- [Monitoring](#monitoring)
- [Attack Simulations](#attack-simulations)
- [Response Procedures](#response-procedures)
- [Dashboard and Visualization](#dashboard-and-visualization)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **Complete NIDS Setup**: Full Suricata installation and configuration for Linux environments
- **Custom Detection Rules**: Specialized rules for reconnaissance, flood attacks, and suspicious behavior
- **Real-time Monitoring**: Live alert monitoring with fast.log and detailed eve.json logging
- **Attack Simulations**: Safe test procedures for validating detection capabilities
- **SOC-Style Response**: Professional incident response procedures and log investigation
- **Visualization Dashboard**: Python-based log parsing and visualization tools
- **Threshold-Based Detection**: Intelligent alerting with configurable thresholds
- **Production Ready**: Optimized configuration for high-performance network monitoring

## 🔧 Prerequisites

### System Requirements
- **Operating System**: Ubuntu 18.04+ or Kali Linux
- **RAM**: Minimum 2GB (4GB recommended)
- **Network Interface**: Dedicated interface for monitoring (or promiscuous mode)
- **Python**: 3.7+ (for visualization tools)

### Network Requirements
- Administrative access to network interfaces
- Ability to set interfaces in promiscuous mode
- Firewall rules allowing packet capture

## 🚀 Installation

### 1. System Update
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Suricata
```bash
sudo apt install suricata -y
```

### 3. Verify Installation
```bash
suricata --version
suricata --list-runmodes
```

### 4. Install Python Dependencies (for visualization)
```bash
pip3 install -r requirements.txt
```

### 5. Enable and Start Service
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

## ⚙️ Configuration

### Interface Configuration

1. **Identify Network Interfaces**:
   ```bash
   ip addr show
   ```

2. **Configure Suricata Interface** (replace `eth0` with your interface):
   ```bash
   sudo nano /etc/suricata/suricata.yaml
   ```

   Locate the `af-packet` section and configure:
   ```yaml
   af-packet:
     - interface: eth0
       cluster-id: 99
       cluster-type: cluster_flow
       defrag: yes
   ```

3. **Set Interface to Promiscuous Mode**:
   ```bash
   sudo ip link set eth0 promisc on
   ```

### Logging Configuration

The provided `suricata.yaml` includes:
- **fast.log**: Simple alert format for quick monitoring
- **eve.json**: Detailed JSON logging for analysis
- **Log Rotation**: Automatic log management

### Rule Configuration

1. **Copy Custom Rules**:
   ```bash
   sudo cp custom.rules /etc/suricata/rules/
   ```

2. **Update Rule Files in Config**:
   Ensure `suricata.yaml` includes:
   ```yaml
   rule-files:
     - suricata.rules
     - custom.rules
   ```

## 🔍 Custom Detection Rules

All custom rules include alert messages, threshold logic, and unique SIDs for easy identification.

### Reconnaissance Detection

#### SYN Scan Detection
```
alert tcp any any -> any any (msg:"SYN Scan Detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000001;)
```
- **Purpose**: Detects TCP SYN scans
- **Threshold**: 10 SYN packets from same source in 60 seconds

#### Nmap Scan Detection
```
alert tcp any any -> any any (msg:"Nmap Scan Detected"; flags:S; seq:0; ack:0; window:1024; threshold:type threshold, track by_src, count 5, seconds 30; sid:1000002;)
```
- **Purpose**: Identifies Nmap scanning patterns
- **Threshold**: 5 suspicious packets in 30 seconds

### Flood Detection

#### ICMP Flood Detection
```
alert icmp any any -> any any (msg:"ICMP Flood Detected"; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000003;)
```
- **Purpose**: Detects ICMP flood attacks
- **Threshold**: 100 ICMP packets in 10 seconds

#### UDP Flood Detection
```
alert udp any any -> any any (msg:"UDP Flood Detected"; threshold:type threshold, track by_src, count 1000, seconds 10; sid:1000004;)
```
- **Purpose**: Identifies UDP flood attacks
- **Threshold**: 1000 UDP packets in 10 seconds

### Suspicious Behavior Detection

#### SSH Brute Force Detection
```
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000005;)
```
- **Purpose**: Detects SSH brute force attempts
- **Threshold**: 5 connection attempts in 60 seconds

#### Port Scan Detection
```
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; sid:1000006;)
```
- **Purpose**: Identifies comprehensive port scanning
- **Threshold**: 20 SYN packets to different ports in 60 seconds

## ▶️ Running Suricata

### IDS Mode Operation

1. **Stop Service for Manual Operation**:
   ```bash
   sudo systemctl stop suricata
   ```

2. **Run in IDS Mode**:
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```

3. **Background Operation**:
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
   ```

4. **Service Mode**:
   ```bash
   sudo systemctl start suricata
   ```

### Testing Configuration

```bash
sudo suricata -c /etc/suricata/suricata.yaml -T
```

## 📊 Monitoring

### Log Files

- **fast.log**: `/var/log/suricata/fast.log` - Simple alert format
- **eve.json**: `/var/log/suricata/eve.json` - Detailed JSON events

### Live Alert Monitoring

#### Monitor Fast Log
```bash
tail -f /var/log/suricata/fast.log
```

#### Monitor EVE JSON
```bash
tail -f /var/log/suricata/eve.json | jq '.'
```

### Alert Filtering

#### Filter by Source IP
```bash
jq 'select(.event_type == "alert" and .src_ip == "192.168.1.100")' /var/log/suricata/eve.json
```

#### Filter by Alert Signature
```bash
jq 'select(.event_type == "alert" and (.alert.signature | contains("Scan")))' /var/log/suricata/eve.json
```

#### Count Alerts by Type
```bash
jq -r '.alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -nr
```

#### Recent Alerts (Last Hour)
```bash
jq 'select(.timestamp | strptime("%Y-%m-%dT%H:%M:%S") | mktime > (now - 3600))' /var/log/suricata/eve.json
```

## 🧪 Attack Simulations

**⚠️ WARNING**: Only perform these simulations in controlled test environments. Never run against production systems without explicit permission.

### Nmap Scan Simulation
```bash
nmap -sS -p 1-100 target_ip
```

### Ping Flood Simulation
```bash
hping3 --icmp --flood --count 200 target_ip
```

### UDP Flood Simulation
```bash
hping3 --udp --flood --count 1000 target_ip
```

### Brute Force Simulation
```bash
for i in {1..10}; do ssh -o ConnectTimeout=1 user@target_ip; done
```

### Port Scan Simulation
```bash
nmap -p 1-1000 target_ip
```

## 🚨 Response Procedures

### SOC-Style Incident Response

#### 1. Alert Triage
- **Review Alert Details**: Examine signature, source, destination, and timestamp
- **Assess Severity**: Evaluate potential impact and likelihood of false positive
- **Correlate Events**: Check for related alerts or patterns

#### 2. Log Investigation
- **Extract Packet Data**: Review full packet captures if available
- **Timeline Analysis**: Map event sequence and duration
- **Context Gathering**: Collect related system and network logs

#### 3. Containment and Blocking
- **IP Blocking**: Implement temporary blocks for malicious sources
  ```bash
  sudo iptables -A INPUT -s malicious_ip -j DROP
  ```
- **Rate Limiting**: Apply traffic shaping for flood attacks
- **Service Isolation**: Segment affected systems if compromised

#### 4. Recovery and Lessons Learned
- **System Cleanup**: Remove malware and restore from backups
- **Rule Tuning**: Adjust thresholds based on false positives
- **Documentation**: Record incident details for future reference

## 📈 Dashboard and Visualization

### EVE Log Parser

The included `eve_parser.py` script provides basic visualization capabilities:

#### Installation
```bash
pip3 install -r requirements.txt
```

#### Usage
```bash
python3 eve_parser.py /var/log/suricata/eve.json
```

#### Features
- **Alert Signature Analysis**: Bar chart of top alert types
- **Source IP Analysis**: Visualization of most active sources
- **Real-time Parsing**: Processes large log files efficiently

#### Advanced Filtering
```bash
# Filter alerts by time range
jq 'select(.timestamp > "2024-01-01T00:00:00")' /var/log/suricata/eve.json > recent_alerts.json

# Generate custom reports
python3 eve_parser.py recent_alerts.json
```

### Integration with ELK Stack (Optional)

For advanced visualization:
1. Install Elasticsearch, Logstash, Kibana
2. Configure Suricata to output to Elasticsearch
3. Create custom dashboards for real-time monitoring

## 📖 Usage

### Basic Operation

1. **Start Monitoring**:
   ```bash
   sudo systemctl start suricata
   ```

2. **Monitor Logs**:
   ```bash
   tail -f /var/log/suricata/fast.log
   ```

3. **Run Simulations** (in test environment):
   ```bash
   # From another machine
   nmap -sS target_ip
   ```

4. **Analyze Results**:
   ```bash
   python3 eve_parser.py /var/log/suricata/eve.json
   ```

### Advanced Configuration

- **Custom Rules**: Edit `custom.rules` and reload Suricata
- **Threshold Tuning**: Adjust threshold values based on network traffic
- **Interface Changes**: Update `suricata.yaml` for different interfaces

## 🔧 Troubleshooting

### Common Issues

#### Suricata Won't Start
```bash
# Check configuration
sudo suricata -c /etc/suricata/suricata.yaml -T

# Check system logs
sudo journalctl -u suricata
```

#### No Alerts Generated
- Verify interface is in promiscuous mode
- Check rule syntax: `suricata -c /etc/suricata/suricata.yaml --list-rules`
- Confirm traffic is flowing through monitored interface

#### High CPU Usage
- Reduce `max-pending-packets`
- Adjust `detect-engine` profile to "low"
- Consider hardware acceleration

#### Log Rotation Issues
```bash
# Manual log rotation
sudo logrotate /etc/logrotate.d/suricata
```

### Performance Tuning

```yaml
# In suricata.yaml
detect-engine:
  - profile: medium
  - custom-values:
      toclient-groups: 3
      toserver-groups: 25

max-pending-packets: 1024
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Test all changes in a virtual environment
- Update documentation for new features
- Follow existing code style and formatting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

This setup is provided for educational and security research purposes. Users are responsible for complying with applicable laws and regulations when deploying network monitoring solutions. Always obtain proper authorization before monitoring networks or systems.

---

**Last Updated**: February 22, 2026
**Version**: 1.0.0