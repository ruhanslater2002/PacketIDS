import scapy.all as scapy
from consolelogger import ConsoleLogger
from packetanalyzer import PacketAnalyzer


class IntrusionDetectionSystem:
    def __init__(self, scan_threshold: int, time_window: int, interface: str):
        # Initialize Scapy and logger
        scapy.conf.verb = 0  # Suppress verbose Scapy output
        self.interface: str = interface
        self.logger: ConsoleLogger = ConsoleLogger("IDS")  # Logger instance for IDS
        self.packet_analyzer: PacketAnalyzer = PacketAnalyzer(self.logger, scan_threshold, time_window)

    def scan(self):
        # Start packet sniffing
        self.logger.info("Intrusion Detection System started...")
        scapy.sniff(filter="tcp or icmp", iface=self.interface, prn=self.packet_analyzer.analyze_packet, store=False)
