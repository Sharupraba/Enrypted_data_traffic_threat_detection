import threading
import logging
from typing import Callable, Optional
from scapy.all import sniff, conf

logger = logging.getLogger("zenith.ingestion.live")

def scapy_packet_to_dict(packet) -> Optional[dict]:
    """
    Converts a Scapy packet into a standard header-only packet dictionary.
    Excludes all non-handshake payload bytes to enforce privacy boundaries.
    """
    if not packet.haslayer("IP"):
        return None

    ip_layer = packet["IP"]
    timestamp = float(packet.time)
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    ttl = int(ip_layer.ttl)
    ip_flags = int(ip_layer.flags)
    
    # Determine protocol
    protocol = "TCP" if ip_layer.proto == 6 else ("UDP" if ip_layer.proto == 17 else "ICMP" if ip_layer.proto == 1 else "OTHER")
    if protocol not in ["TCP", "UDP"]:
        return None

    src_port = 0
    dst_port = 0
    tcp_flags = None
    tls_raw = None
    dns_info = None

    if protocol == "TCP" and packet.haslayer("TCP"):
        tcp_layer = packet["TCP"]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)
        
        # Extract raw TCP payload bytes only if it starts with a TLS handshake signature
        payload = bytes(tcp_layer.payload)
        if payload and payload.startswith(b"\x16\x03"):
            tls_raw = payload
    elif protocol == "UDP" and packet.haslayer("UDP"):
        udp_layer = packet["UDP"]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        
        # Extract DNS details (queries and response codes) if present
        if packet.haslayer("DNS"):
            dns_layer = packet["DNS"]
            qname = None
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname).rstrip(".")
            dns_info = {
                "qname": qname,
                "rcode": int(dns_layer.rcode) if dns_layer.rcode is not None else None,
                "qr": int(dns_layer.qr) if dns_layer.qr is not None else None
            }

    pkt_len = len(packet)

    return {
        "timestamp": timestamp,
        "src_mac": packet.src,
        "dst_mac": packet.dst,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "ip_flags": ip_flags,
        "ttl": ttl,
        "tcp_flags": tcp_flags,
        "pkt_len": pkt_len,
        "tls_raw": tls_raw,
        "dns_info": dns_info
    }


class LiveSniffer:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.interface: Optional[str] = None
        self.callback: Optional[Callable] = None
        self.is_running = False

    def list_interfaces(self) -> list[dict]:
        """
        List available network interfaces on the host machine.
        """
        try:
            interfaces = []
            for key, dev in conf.ifaces.items():
                interfaces.append({
                    "name": dev.name,
                    "description": dev.description or dev.name,
                    "pcap_name": key
                })
            return interfaces
        except Exception as e:
            logger.error(f"Error listing interfaces: {e}")
            return []

    def _packet_callback(self, packet):
        if self._stop_event.is_set():
            return
        
        try:
            pkt_dict = scapy_packet_to_dict(packet)
            if pkt_dict and self.callback:
                self.callback(pkt_dict)
        except Exception as e:
            logger.error(f"Error in packet callback: {e}")

    def start(self, interface: str, callback: Callable):
        """
        Start sniffing on the specified interface.
        """
        if self.is_running:
            logger.warning("Sniffer is already running.")
            return

        self.interface = interface
        self.callback = callback
        self._stop_event.clear()
        self.is_running = True

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Live capture started on interface: {interface}")

    def _run(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                stop_filter=lambda p: self._stop_event.is_set(),
                filter="ip and (tcp or udp)",
                store=0
            )
        except Exception as e:
            logger.error(f"Error during sniffing loop on {self.interface}: {e}")
        finally:
            self.is_running = False
            logger.info(f"Sniffer thread stopped for interface: {self.interface}")

    def stop(self):
        """
        Stop sniffing.
        """
        if not self.is_running:
            return
        
        self._stop_event.set()
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Live capture stopped.")
