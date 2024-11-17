from consolelogger import ConsoleLogger
import scapy.all as scapy
import time
from termcolor import colored


class PacketAnalyzer:
    def __init__(self, logger: ConsoleLogger, scan_threshold: int, time_window: float):
        self.logger: ConsoleLogger = logger
        self.scan_threshold: int = scan_threshold
        self.time_window: float = time_window
        self.traffic_logs: dict = {}

    def check_log(self, source_ip: str, current_time: float) -> None:
        if source_ip not in self.traffic_logs:
            self.traffic_logs[source_ip] = {'timestamp': current_time, 'ports': set()}  # Creates a log with the current timestamp

    def update_log(self, current_time: float, dest_port: int, source_ip: str) -> None:
        if source_ip not in self.traffic_logs:
            return  # Exit early if no log for source_ip exists.
        # Remove old timestamps if outside the time window
        if current_time - self.traffic_logs[source_ip]['timestamp'] > self.time_window:
            self.logger.info(
                f"Log for {colored(source_ip, 'yellow')} has been cleared, out of time window {colored(int(self.time_window), 'yellow')}.")
            self.traffic_logs.pop(source_ip, None)
            return
        # Update log with current time and destination port
        self.traffic_logs[source_ip]['timestamp'] = current_time
        self.traffic_logs[source_ip]['ports'].add(dest_port)

    def analyze_packet(self, packet: scapy.packet.Packet) -> None:
        try:
            if packet.haslayer(scapy.IP):
                if packet.haslayer(scapy.TCP):
                    self.handle_tcp_packet(packet)
                elif packet.haslayer(scapy.ICMP):
                    self.handle_icmp_packet(packet)
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {str(e)}")

    def handle_tcp_packet(self, packet: scapy.packet.Packet) -> None:
        try:
            flag: scapy.packet.Packet = packet[scapy.TCP].flags
            if flag == "S":  # SYN flag for port scanning
                source_ip: str = packet[scapy.IP].src
                dst_port: int = packet[scapy.TCP].dport
                current_time: float = time.time()
                self.check_log(source_ip, current_time)
                self.update_log(current_time, dst_port, source_ip)
                self.detect_port_scan(source_ip, dst_port)
        except Exception as e:
            self.logger.error(f"Error handling TCP packet: {str(e)}")

    def handle_icmp_packet(self, packet: scapy.packet.Packet) -> None:
        try:
            if packet[scapy.ICMP].type == 8:  # ICMP Echo Request (ping)
                source_ip: str = packet[scapy.IP].src
                self.detect_icmp_scan(source_ip)
        except Exception as e:
            self.logger.error(f"Error handling ICMP packet: {str(e)}")

    def detect_port_scan(self, source_ip: str, latest_scn_port: int) -> None:
        # Check if the number of unique ports exceeds the scan threshold
        if len(self.traffic_logs[source_ip]['ports']) > self.scan_threshold:
            self.logger.warning(
                f"Potential port scan detected from IP: {colored(source_ip, 'red')}, dst port: {colored(latest_scn_port, 'red')}.")

    def detect_icmp_scan(self, source_ip: str) -> None:
        # Simple ICMP scan detection (can be extended for frequency analysis)
        self.logger.warning(f"ICMP scan from IP: {colored(source_ip, 'yellow')}.")
