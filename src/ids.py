import scapy.all as scapy
from termcolor import colored
from packethandler import PacketHandler
from typing import List
from ConsoleLogger import ConsoleLogger
import time


class IntrusionDetectionSystem:
    def __init__(self, scan_threshold: int, time_window: int):
        scapy.conf.verb = 0  # Suppress verbose Scapy output
        self.logger = ConsoleLogger("IDS")  # Logger instance for IDS
        self.packet_handler = PacketHandler()  # Packet handler instance
        self.scan_threshold = scan_threshold  # Threshold for port scans
        self.time_window = time_window  # Time window for detecting suspicious activity
        self.traffic_logs: List[dict] = []  # Logs to track traffic by IP

    def scan(self):
        """Start sniffing packets."""
        self.logger.info("Intrusion Detection System started...")
        scapy.sniff(
            filter="tcp or icmp",
            iface="VMware Network Adapter VMnet8",  # Replace with your interface name
            prn=self.analyze_packet,
            store=False
        )

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        """Analyze packets and check for suspicious behavior."""
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            tcp_data: dict = self.packet_handler.handle_tcp_packet(packet)
            traffic_log = self.get_log(tcp_data["source_ip"])
            self.update_log(traffic_log, time.time(), tcp_data["dst_port"])
            self.detect_port_scan(traffic_log, tcp_data["source_ip"])
        elif packet.haslayer(scapy.ICMP) and packet.haslayer(scapy.IP):
            self.packet_handler.handle_icmp_packet(packet)

    def get_log(self, source_ip: str) -> dict:
        """Find or create a log entry for the given IP."""
        for log in self.traffic_logs:
            if log['ip'] == source_ip:
                return log
        return self.create_log(source_ip)

    def create_log(self, source_ip: str) -> dict:
        """Create and append a new log entry."""
        traffic_log = {'ip': source_ip, 'timestamps': [], 'ports': set()}
        self.traffic_logs.append(traffic_log)
        return traffic_log

    def update_log(self, log: dict, current_time: float, dest_port: int) -> None:
        """Update the traffic log and clean up old entries."""
        log['timestamps'].append(current_time)
        log['ports'].add(dest_port)
        log['timestamps'] = [
            timestamp for timestamp in log['timestamps']
            if current_time - timestamp <= self.time_window
        ]

    def detect_port_scan(self, traffic_log: dict, source_ip: str) -> None:
        """Detect port scanning behavior."""
        if len(traffic_log['ports']) > self.scan_threshold:
            self.logger.warning(
                f"Potential port scan detected from IP: {colored(source_ip, 'red')} "
                f"scanning ports: {traffic_log['ports']}."
            )
