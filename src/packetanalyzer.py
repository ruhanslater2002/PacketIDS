from consolelogger import ConsoleLogger
from trafficlogmanager import TrafficLogManager
import scapy.all as scapy
import time
from termcolor import colored


class PacketAnalyzer:
    def __init__(self, logger: ConsoleLogger, traffic_log_manager: TrafficLogManager, scan_threshold: int, time_window: int):
        self.logger = logger
        self.traffic_log_manager = traffic_log_manager
        self.scan_threshold = scan_threshold
        self.time_window = time_window

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            self.handle_tcp_packet(packet)
        elif packet.haslayer(scapy.ICMP) and packet.haslayer(scapy.IP):
            self.handle_icmp_packet(packet)

    def handle_tcp_packet(self, packet: scapy.packet.Packet) -> None:
        source_ip: str = packet[scapy.IP].src
        dst_port: int = packet[scapy.TCP].dport
        current_time: float = time.time()
        traffic_log: dict = self.traffic_log_manager.get_log(source_ip)
        self.traffic_log_manager.update_log(traffic_log, current_time, dst_port)
        self.detect_port_scan(traffic_log, source_ip)

    def handle_icmp_packet(self, packet: scapy.packet.Packet) -> None:
        source_ip: str = packet[scapy.IP].src
        self.logger.warning(f"ICMP scan detected from IP: {colored(source_ip, 'yellow')}.")

    def detect_port_scan(self, traffic_log: dict, source_ip: str) -> None:
        if len(traffic_log['ports']) > self.scan_threshold:  # Use scan_threshold here
            self.logger.warning(
                f"Potential port scan detected from IP: {colored(source_ip, 'red')} scanning ports: {traffic_log['ports']}.")
