import scapy.all as scapy
from collections import defaultdict
import time
from typing import List, DefaultDict
from ConsoleLogger import ConsoleLogger


class IntrusionDetectionSystem:
    def __init__(self, scan_threshold: int, time_window: int):
        # Initialize Scapy and logger
        scapy.conf.verb = 0  # Suppress verbose Scapy output
        self.logger: ConsoleLogger = ConsoleLogger("IDS")  # Logger instance for IDS
        # Threshold settings for detecting scans
        self.SCAN_THRESHOLD = scan_threshold  # Max packets from a single IP in the time window
        self.TIME_WINDOW = time_window  # Time window in seconds for detecting suspicious activity
        # Traffic logs to track packets per IP
        self.traffic_log: DefaultDict[str, List[float]] = defaultdict(list)
        # Start packet sniffing
        self.logger.info("Starting Intrusion Detection System...")
        scapy.sniff(filter="tcp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        """
        Analyze incoming packets to detect potential scans or suspicious activity.

        Args:
            packet (scapy.packet.Packet): The incoming packet to analyze.
        """
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            # Extract source IP, destination port, and TCP flags
            source_ip: str = packet[scapy.IP].src
            dest_port: int = packet[scapy.TCP].dport
            flags: int = packet[scapy.TCP].flags
            # Log the packet's timestamp
            current_time: float = time.time()
            self.traffic_log[source_ip].append(current_time)
            # Remove old entries outside the time window
            self.traffic_log[source_ip] = [
                timestamp for timestamp in self.traffic_log[source_ip]
                if current_time - timestamp <= self.TIME_WINDOW
            ]
            # Detect scan based on the threshold
            if len(self.traffic_log[source_ip]) > self.SCAN_THRESHOLD:
                self.logger.warning(f"Potential scan detected from IP: {source_ip}.")
                self.logger.info(f"Packets in the last {self.TIME_WINDOW} seconds: {len(self.traffic_log[source_ip])}.")
                # Optional: Take further action (e.g., block the IP)
            # Detect SYN packets (common in scans)
            if flags & 0x02:  # SYN flag
                self.logger.warning(f"SYN packet detected from {source_ip} to port {dest_port}.")
