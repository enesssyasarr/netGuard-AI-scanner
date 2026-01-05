import logging
from scapy.all import sniff, IP, TCP
from datetime import datetime

class TrafficSniffer:
    """A class for capturing and pre-filtering network traffic."""
    
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        logging.basicConfig(
            filename='logs/security_events.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def packet_callback(self, packet):
        """Processing each intercepted packet."""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if packet.haslayer(TCP):
                # An example of a simple heuristic: fixing suspicious ports
                if packet[TCP].dport == 4444 or packet[TCP].dport == 1337:
                    self._report_alert(src_ip, dst_ip, packet[TCP].dport)

    def _report_alert(self, src: str, dst: str, port: int):
        message = f"🚨 SUSPICIOUS ACTIVITY: {src} -> {dst} to the port {port}"
        print(message)
        logging.warning(message)

    def start_capture(self, count: int = 0):
        """Start listening on the interface."""
        print(f"[*] Starting monitoring on the interface {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_callback, store=0, count=count)
