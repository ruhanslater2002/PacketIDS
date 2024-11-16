import scapy.all as scapy
from collections import defaultdict
import time
from typing import List
from ConsoleLogger import ConsoleLogger


class IntrusionDetectionSystem:
    def __init__(self, scan_threshold: int, time_window: int):
        # Initialize Scapy and logger
        scapy.conf.verb = 0  # Suppress verbose Scapy output
        self.logger: ConsoleLogger = ConsoleLogger("IDS")  # Logger instance for IDS
        # Threshold settings for detecting scans
        self.scan_threshold = scan_threshold  # Max packets from a single IP in the time window
        self.time_window = time_window  # Time window in seconds for detecting suspicious activity
        # Traffic logs to track packets per IP and port
        self.traffic_log: List[dict] = []  # List to store logs for each source IP
        # Start packet sniffing
        self.logger.info("Starting Intrusion Detection System...")
        scapy.sniff(filter="tcp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            # Extract source IP, destination port, and TCP flags
            source_ip: str = packet[scapy.IP].src
            dest_port: int = packet[scapy.TCP].dport
            flags: int = packet[scapy.TCP].flags
            # Log the packet's timestamp
            current_time: float = time.time()
            # Find the existing traffic log for the source IP
            ip_log: dict = next((log for log in self.traffic_log if log['ip'] == source_ip), None)
            if ip_log is None:
                # If no existing log found for the source IP, create one
                ip_log: dict = {'ip': source_ip, 'timestamps': [], 'ports': set()}  # Use a set for ports
                self.traffic_log.append(ip_log)
            # Add current packet's timestamp and port to the log for the source IP
            ip_log['timestamps'].append(current_time)
            ip_log['ports'].add(dest_port)  # Track scanned ports
            # Remove old entries outside the time window
            ip_log['timestamps'] = [
                timestamp for timestamp in ip_log['timestamps']
                if current_time - timestamp <= self.time_window
            ]
            # Detect scan based on the threshold (number of packets)
            if len(ip_log['timestamps']) > self.scan_threshold:
                self.logger.warning(f"Potential scan detected from IP: {source_ip}.")
                self.logger.info(f"Packets in the last {self.time_window} seconds: {len(ip_log['timestamps'])}.")
                # Optional: Take further action (e.g., block the IP)
            # Detect port scanning (if same IP is scanning multiple ports)
            if len(ip_log['ports']) > 5:  # Arbitrary threshold for port scanning detection
                self.logger.warning(f"Port scan detected from IP: {source_ip} scanning ports: {ip_log['ports']}.")
            # Detect SYN packets (common in scans)
            if flags & 0x02:  # SYN flag
                self.logger.warning(f"SYN packet detected from {source_ip} to port {dest_port}.")
