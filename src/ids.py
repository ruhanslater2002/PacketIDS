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
        self.icmp_logs: List[dict] = []  # List to store ICMP logs for scan detection

    def scan(self):
        # Start packet sniffing
        self.logger.info("Intrusion Detection System started...")
        scapy.sniff(filter="tcp or icmp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            self.handle_tcp_packet(packet)
        elif packet.haslayer(scapy.ICMP) and packet.haslayer(scapy.IP):
            self.handle_icmp_packet(packet)

    def handle_tcp_packet(self, packet: scapy.packet.Packet) -> None:
        source_ip: str = packet[scapy.IP].src
        dst_port: int = packet[scapy.TCP].dport
        current_time: float = time.time()
        traffic_log: dict = self.get_log(source_ip)
        self.update_log(traffic_log, current_time, dst_port)
        self.detect_port_scan(traffic_log, source_ip)

    def handle_icmp_packet(self, packet: scapy.packet.Packet) -> None:
        source_ip: str = packet[scapy.IP].src
        icmp_type: int = packet[scapy.ICMP].type
        current_time: float = time.time()
        if icmp_type == 8:  # Echo request (ping)
            icmp_log: dict = self.get_icmp_log(source_ip)
            self.update_icmp_log(icmp_log, current_time)
            self.detect_icmp_scan(icmp_log, source_ip)

    def get_log(self, source_ip: str) -> dict:
        for traffic_log in self.traffic_logs:
            if traffic_log['ip'] == source_ip:
                return traffic_log
        return self.create_log(source_ip)

    def get_icmp_log(self, source_ip: str) -> dict:
        for icmp_log in self.icmp_logs:
            if icmp_log['ip'] == source_ip:
                return icmp_log
        return self.create_icmp_log(source_ip)

    def create_log(self, source_ip: str) -> dict:
        traffic_log: dict = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_logs.append(traffic_log)
        return traffic_log

    def create_icmp_log(self, source_ip: str) -> dict:
        icmp_log: dict = {'ip': source_ip, 'timestamps': []}
        self.icmp_logs.append(icmp_log)
        return icmp_log

    def update_log(self, log: dict, current_time: float, dest_port: int) -> None:
        log['timestamps'].append(current_time)
        log['ports'].add(dest_port)
        log['timestamps'] = [
            timestamp for timestamp in log['timestamps']
            if current_time - timestamp <= self.time_window
        ]

    def update_icmp_log(self, icmp_log: dict, current_time: float) -> None:
        icmp_log['timestamps'].append(current_time)
        icmp_log['timestamps'] = [
            timestamp for timestamp in icmp_log['timestamps']
            if current_time - timestamp <= self.time_window
        ]

    def detect_port_scan(self, traffic_log: dict, source_ip: str) -> None:
        if len(traffic_log['ports']) > 4:  # Arbitrary threshold for port scanning detection
            self.logger.warning(f"Potential port scan detected from IP: {colored(source_ip, 'red')} scanning ports: {traffic_log['ports']}.")

    def detect_icmp_scan(self, icmp_log: dict, source_ip: str) -> None:
        if len(icmp_log['timestamps']) > self.scan_threshold:  # Check if ICMP echo requests exceed threshold
            self.logger.warning(f"Potential ICMP scan detected from IP: {colored(source_ip, 'blue')}.")
