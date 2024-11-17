from consolelogger import ConsoleLogger
import scapy.all as scapy
import time
from termcolor import colored


class PacketAnalyzer:
    def __init__(self, logger: ConsoleLogger, scan_threshold: int, time_window: int):
        self.logger = logger
        self.scan_threshold = scan_threshold
        self.time_window = time_window
        self.traffic_logs = []

    def get_log(self, source_ip: str) -> dict:
        # Check if the log for the IP already exists, else create one
        for traffic_log in self.traffic_logs:
            if traffic_log['ip'] == source_ip:
                return traffic_log
        return self.create_log(source_ip)

    def create_log(self, source_ip: str) -> dict:
        # Create a new log entry for the IP
        traffic_log = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_logs.append(traffic_log)
        return traffic_log

    def update_log(self, log: dict, current_time: float, dest_port: int) -> None:
        # Update timestamps and ports in the traffic log
        log['timestamps'].append(current_time)
        log['ports'].add(dest_port)
        # Remove old timestamps that are outside the time window
        log['timestamps'] = [timestamp for timestamp in log['timestamps'] if current_time - timestamp <= self.time_window]

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.IP):
            if packet.haslayer(scapy.TCP):
                self.handle_tcp_packet(packet)
            elif packet.haslayer(scapy.ICMP):
                self.handle_icmp_packet(packet)

    def handle_tcp_packet(self, packet: scapy.packet.Packet) -> None:
        flag: scapy.packet.Packet = packet[scapy.TCP].flags
        if flag == "S":  # Handles only type requested flags
            source_ip: str = packet[scapy.IP].src
            dst_port: int = packet[scapy.TCP].dport
            current_time: float = time.time()
            # Get or create traffic log for the source IP
            traffic_log = self.get_log(source_ip)
            self.update_log(traffic_log, current_time, dst_port)
            self.detect_port_scan(traffic_log, source_ip, dst_port)

    def handle_icmp_packet(self, packet: scapy.packet.Packet) -> None:
        if packet[scapy.ICMP].type == 8:  # Handles only type 8 request code
            source_ip: str = packet[scapy.IP].src
            self.detect_icmp_scan(source_ip)

    def detect_port_scan(self, traffic_log: dict, source_ip: str, latest_scn_port: int) -> None:
        # If the number of unique ports exceeds the scan threshold, it's a port scan
        if len(traffic_log['ports']) > self.scan_threshold:
            self.logger.warning(f"Potential port scan detected from IP: {colored(source_ip, 'red')} scanning ports: {latest_scn_port}.")

    def detect_icmp_scan(self, source_ip: str):
        self.logger.warning(f"ICMP scan detected from IP: {colored(source_ip, 'yellow')}.")
