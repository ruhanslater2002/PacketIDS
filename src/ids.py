import scapy.all as scapy
from collections import defaultdict
import time
from typing import List, DefaultDict
from ConsoleLogger import ConsoleLogger


class Ids:
    def __init__(self):
        scapy.conf.verb = 0  # Verbose
        self.logger: ConsoleLogger = ConsoleLogger("IDS")
        # Threshold settings
        self.SCAN_THRESHOLD: int = 20  # Number of packets per IP within the window
        self.TIME_WINDOW: int = 10  # Time window in seconds for checking excessive traffic
        # Track packets from each IP
        self.traffic_log: DefaultDict[str, List[float]] = defaultdict(list)
        # Start packet sniffing
        self.logger.info("Starting IDS...")
        scapy.sniff(filter="tcp", prn=self.detect_scan, store=False)

    def detect_scan(self, pkt: scapy.packet.Packet) -> None:
        """Detect suspicious packets (port scans, etc.)."""
        if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.IP):
            src_ip: str = pkt[scapy.IP].src
            dst_port: int = pkt[scapy.TCP].dport
            # Log packet information
            current_time: float = time.time()
            self.traffic_log[src_ip].append(current_time)
            # Remove outdated logs
            self.traffic_log[src_ip] = [t for t in self.traffic_log[src_ip] if current_time - t <= self.TIME_WINDOW]
            # Detect scan
            if len(self.traffic_log[src_ip]) > self.SCAN_THRESHOLD:
                self.logger.warning(f"[ALERT] Potential scan detected from IP: {src_ip}")
                self.logger.info(f"Packets in the last {self.TIME_WINDOW}s: {len(self.traffic_log[src_ip])}")
                # Optional: Block IP or trigger an alert.
            # Check for SYN flag
            flags: int = pkt[scapy.TCP].flags
            if flags & 0x02:  # SYN flag
                self.logger.warning(f"SYN packet detected from {src_ip} to port {dst_port}")
