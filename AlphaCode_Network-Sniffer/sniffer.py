import argparse
import logging
import threading
import time
from collections import Counter, defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw

ALERT_LOG = "alerts.log"

# Configure logging
logger = logging.getLogger("ids_sniffer")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(ALERT_LOG)
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


class Analyzer:
    def __init__(self, window=10):
        # sliding window in seconds
        self.window = window
        self.pkt_counts = defaultdict(lambda: deque())  # src -> timestamps
        self.icmp_counts = defaultdict(lambda: deque())
        self.syn_records = defaultdict(lambda: deque())  # src -> deque of (dstport, ts)
        self.port_attempts = defaultdict(lambda: defaultdict(lambda: deque()))  # src->dstport->deque(ts)
        self.top_talkers = Counter()
        self.protocol_counts = Counter()
        self.uncommon_ports = {6667, 31337, 1337, 8081, 9001}

        # DNS tracking
        self.dns_queries = defaultdict(lambda: deque())  # src -> deque of (qname, ts)
        self.dns_window = 60
        self.dns_unique_threshold = 20

        # thresholds (tunable)
        self.syn_scan_threshold_unique_ports = 10
        self.syn_scan_window = 10
        self.icmp_flood_threshold = 50
        self.icmp_window = 5
        self.high_traffic_threshold = 200
        self.high_traffic_window = 10
        self.repeated_conn_threshold = 20
        self.repeated_conn_window = 10

    def _prune(self, dq, now):
        while dq and dq[0] < now - self.window:
            dq.popleft()

    def register_packet(self, pkt_info):
        now = time.time()
        src = pkt_info.get('src')
        proto = pkt_info.get('proto')
        dst_port = pkt_info.get('dport')

        # top talkers and protocol counts
        if src:
            self.top_talkers[src] += 1
            self.pkt_counts[src].append(now)
            self._prune(self.pkt_counts[src], now)

        if proto:
            self.protocol_counts[proto] += 1

        # ICMP
        if proto == 'ICMP' and src:
            self.icmp_counts[src].append(now)
            self._prune(self.icmp_counts[src], now)
            if len(self.icmp_counts[src]) >= self.icmp_flood_threshold:
                self.raise_alert(src, pkt_info.get('dst'), 'ICMP Flood', 'High')

        # TCP SYN related
        flags = pkt_info.get('flags', '')
        if proto == 'TCP' and 'S' in flags and src and dst_port:
            # record unique dst ports for SYN scan detection
            dq = self.syn_records[src]
            dq.append((dst_port, now))
            # prune older than syn_scan_window
            while dq and dq[0][1] < now - self.syn_scan_window:
                dq.popleft()
            unique_ports = {p for p, t in dq}
            if len(unique_ports) >= self.syn_scan_threshold_unique_ports:
                self.raise_alert(src, pkt_info.get('dst'), 'SYN Scan', 'High')

            # repeated connection attempts to same port
            attempts = self.port_attempts[src][dst_port]
            attempts.append(now)
            while attempts and attempts[0] < now - self.repeated_conn_window:
                attempts.popleft()
            if len(attempts) >= self.repeated_conn_threshold:
                self.raise_alert(src, pkt_info.get('dst'), 'Repeated Connection Attempts', 'Medium')

        # high traffic from single IP
        if src:
            # prune with its own window
            now = time.time()
            self._prune(self.pkt_counts[src], now)
            if len(self.pkt_counts[src]) >= self.high_traffic_threshold:
                self.raise_alert(src, pkt_info.get('dst'), 'High Traffic', 'Medium')

        # uncommon ports
        if dst_port and dst_port in self.uncommon_ports:
            self.raise_alert(src, pkt_info.get('dst'), f'Access to Uncommon Port {dst_port}', 'Low')

        # DNS suspicious patterns: many unique qnames from same src
        dns_q = pkt_info.get('dns_qname')
        if proto == 'DNS' and dns_q and src:
            dq = self.dns_queries[src]
            dq.append((dns_q, now))
            # prune older than dns_window
            while dq and dq[0][1] < now - self.dns_window:
                dq.popleft()
            unique_qnames = {q for q, t in dq}
            if len(unique_qnames) >= self.dns_unique_threshold:
                self.raise_alert(src, pkt_info.get('dst'), 'Suspicious DNS Activity', 'Medium')

    def raise_alert(self, src, dst, threat, severity):
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        alert = f"{ts} | src={src} dst={dst} threat={threat} severity={severity}"
        print(alert)
        logger.info(alert)

    def get_top_talkers(self, n=10):
        return self.top_talkers.most_common(n)

    def get_protocol_distribution(self):
        return dict(self.protocol_counts)


def parse_packet(pkt):
    info = {
        'src': None,
        'dst': None,
        'proto': None,
        'sport': None,
        'dport': None,
        'flags': None,
        'payload': None,
    }
    if IP in pkt:
        ip = pkt[IP]
        info['src'] = ip.src
        info['dst'] = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info['proto'] = 'TCP'
            info['sport'] = tcp.sport
            info['dport'] = tcp.dport
            info['flags'] = tcp.flags.flagrepr() if hasattr(tcp.flags, 'flagrepr') else str(tcp.flags)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info['proto'] = 'UDP'
            info['sport'] = udp.sport
            info['dport'] = udp.dport
        elif pkt.haslayer(ICMP):
            info['proto'] = 'ICMP'
        elif pkt.haslayer(DNS):
            info['proto'] = 'DNS'
            try:
                # DNS query name if present
                q = pkt[DNS].qd
                if q and hasattr(q, 'qname'):
                    info['dns_qname'] = q.qname.decode('utf-8', errors='ignore')
            except Exception:
                info['dns_qname'] = None

    # payload
    if Raw in pkt:
        try:
            info['payload'] = pkt[Raw].load.decode('utf-8', errors='replace')
        except Exception:
            info['payload'] = str(pkt[Raw].load)

    # detect simple HTTP by payload
    if info.get('payload'):
        payload_start = info['payload'][:8].upper()
        http_methods = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')
        if any(payload_start.startswith(m) for m in http_methods):
            info['proto'] = 'HTTP'

    return info


def start_visualizer(analyzer, interval=10):
    def run():
        while True:
            time.sleep(interval)
            top = analyzer.get_top_talkers(10)
            proto = analyzer.get_protocol_distribution()
            print('\n=== Top Talkers ===')
            for ip, cnt in top:
                print(f"{ip}: {cnt}")
            print('=== Protocol Distribution ===')
            for p, c in proto.items():
                print(f"{p}: {c}")
            print('======================\n')

    t = threading.Thread(target=run, daemon=True)
    t.start()


def main():
    parser = argparse.ArgumentParser(description='Simple Scapy-based IDS/sniffer')
    parser.add_argument('-i', '--iface', help='Interface to sniff on (optional)', default=None)
    parser.add_argument('--visual', help='Enable periodic visualization', action='store_true')
    args = parser.parse_args()

    analyzer = Analyzer()

    if args.visual:
        start_visualizer(analyzer)

    def process(pkt):
        info = parse_packet(pkt)
        analyzer.register_packet(info)

    print('Starting capture (press Ctrl+C to stop)...')
    sniff(prn=process, store=0, iface=args.iface)


if __name__ == '__main__':
    main()
