import scapy.all as scapy
from termcolor import colored
from ConsoleLogger import ConsoleLogger


class PacketHandler:
    def __init__(self):
        self.logger = ConsoleLogger("PACKET-HANDLER")

    def handle_tcp_packet(self, packet: scapy.packet.Packet) -> dict:
        """Handle incoming TCP packets."""
        source_ip: str = packet[scapy.IP].src
        dst_port: int = packet[scapy.TCP].dport
        self.logger.info(f"TCP packet detected from {colored(source_ip, 'cyan')} to port {dst_port}.")
        return {"source_ip": source_ip, "dst_port": dst_port}  # Pass data back to IDS

    def handle_icmp_packet(self, packet: scapy.packet.Packet) -> None:
        """Handle incoming ICMP packets."""
        source_ip: str = packet[scapy.IP].src
        self.logger.warning(f"ICMP packet detected from {colored(source_ip, 'yellow')}.")
