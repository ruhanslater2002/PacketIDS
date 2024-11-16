import scapy.all as scapy
from termcolor import colored
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
        self.traffic_logs: List[dict] = []  # List to store logs for each source IP
        # example:
        # {'ip': '192.168.1.50', 'timestamps': [timestamp1, timestamp2, ...], 'ports': {80, 443, 8080}},
        # {'ip': '192.168.1.30', 'timestamps': [timestamp3, timestamp4, ...], 'ports': {22, 25}},
        # Start packet sniffing
        self.logger.info("Starting Intrusion Detection System...")
        scapy.sniff(filter="tcp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            source_ip: str = packet[scapy.IP].src
            dst_port: int = packet[scapy.TCP].dport
            flags: int = packet[scapy.TCP].flags
            current_time: float = time.time()
            # Find or create log for the source IP
            log: dict = self.get_log(source_ip)
            # Add timestamp and port to log
            self.update_log(log, current_time, dst_port)
            # Perform scan detection checks
            self.detect_port_scan(log, source_ip)

    def get_log(self, source_ip: str) -> dict:
        # Search for an existing log entry for the given IP
        for log in self.traffic_logs:
            if log['ip'] == source_ip:
                return log  # Return immediately if found
        # If no log entry exists, create a new one
        return self.create_log(source_ip)

    def create_log(self, source_ip: str) -> dict:
        """Create and append a new log entry for the given IP"""
        log: dict = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_logs.append(log)
        return log

    def update_log(self, log: dict, current_time: float, dest_port: int) -> None:
        """Update log with timestamp and destination port. Remove old entries outside the time window."""
        log['timestamps'].append(current_time)
        log['ports'].add(dest_port)
        # Create a new list of valid timestamps by iterating through the existing ones
        valid_timestamps: list = []
        for timestamp in log['timestamps']:
            if current_time - timestamp <= self.time_window:
                valid_timestamps.append(timestamp)
        # Replace the old list with the valid timestamps
        log['timestamps'] = valid_timestamps

    def detect_port_scan(self, log: dict, source_ip: str) -> None:
        if len(log['ports']) > 4:  # Arbitrary threshold for port scanning detection
            self.logger.warning(f"Potential port scan detected from IP: {colored(source_ip, 'red')} scanning ports: {log['ports']}.")
