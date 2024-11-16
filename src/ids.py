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
        self.traffic_log: List[dict] = []  # List to store logs for each source IP
        # example:
        # {'ip': '192.168.1.1', 'timestamps': [timestamp1, timestamp2, ...], 'ports': {80, 443, 8080}},
        # {'ip': '192.168.1.2', 'timestamps': [timestamp3, timestamp4, ...], 'ports': {22, 25}},
        # Start packet sniffing
        self.logger.info("Starting Intrusion Detection System...")
        scapy.sniff(filter="tcp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            source_ip: str = packet[scapy.IP].src
            dest_port: int = packet[scapy.TCP].dport
            flags: int = packet[scapy.TCP].flags
            current_time: float = time.time()
            # Find or create log for the source IP
            ip_log = self.get_ip_log(source_ip)
            # Add timestamp and port to log
            self.update_ip_log(ip_log, current_time, dest_port)
            # Perform scan detection checks
            # self.detect_scan(ip_log, source_ip)
            self.detect_port_scan(ip_log, source_ip)
            # self.detect_syn_scan(flags, source_ip, dest_port)

    def get_ip_log(self, source_ip: str) -> dict:
        # Search for an existing log entry for the given IP
        for log in self.traffic_log:
            if log['ip'] == source_ip:
                return log  # Return immediately if found
        # If no log entry exists, create a new one and append to traffic_log
        ip_log: dict = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_log.append(ip_log)
        return ip_log

    def update_ip_log(self, ip_log: dict, current_time: float, dest_port: int) -> None:
        ip_log['timestamps'].append(current_time)
        ip_log['ports'].add(dest_port)

        # Remove old entries outside the time window
        ip_log['timestamps'] = [
            timestamp for timestamp in ip_log['timestamps']
            if current_time - timestamp <= self.time_window
        ]

    def detect_scan(self, ip_log: dict, source_ip: str) -> None:
        if len(ip_log['timestamps']) > self.scan_threshold:
            self.logger.warning(f"Potential scan detected from IP: {colored(source_ip, 'red')}.")
            self.logger.info(f"Packets in the last {self.time_window} seconds: {colored(len(ip_log['timestamps']), 'red')}.")

    def detect_port_scan(self, ip_log: dict, source_ip: str) -> None:
        if len(ip_log['ports']) > 5:  # Arbitrary threshold for port scanning detection
            self.logger.warning(f"Port scan detected from IP: {colored(source_ip, 'red')} scanning ports: {ip_log['ports']}.")

    def detect_syn_scan(self, flags: int, source_ip: str, dest_port: int) -> None:
        if flags & 0x02:  # SYN flag
            self.logger.warning(f"SYN packet detected from {colored(source_ip, 'red')} to port {colored(dest_port, 'red')}.")
