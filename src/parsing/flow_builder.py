import threading
import uuid
import logging
from typing import Dict, List, Tuple, Optional, Callable
from .packet_parser import parse_packet_headers

logger = logging.getLogger("zenith.parsing.flow")

class FlowRecord:
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, start_time: float):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen = start_time
        self.fwd_packets: List[dict] = []
        self.bwd_packets: List[dict] = []
        
        # TLS client handshake fields
        self.tls_version: Optional[str] = None
        self.cipher_suites: List[int] = []
        self.extensions: List[int] = []
        self.sni: Optional[str] = None
        self.alpn: List[str] = []
        self.ec_curves: List[int] = []
        self.ec_formats: List[int] = []
        
        # TLS server handshake fields
        self.tls_version_negotiated: Optional[str] = None
        self.cipher_suite_negotiated: Optional[int] = None

    def add_packet(self, packet: dict):
        timestamp = packet["timestamp"]
        self.last_seen = max(self.last_seen, timestamp)
        
        # Check direction
        is_fwd = (packet["src_ip"] == self.src_ip and packet["src_port"] == self.src_port)
        
        pkt_info = {
            "timestamp": timestamp,
            "pkt_len": packet["pkt_len"],
            "tcp_flags": packet.get("tcp_flags"),
            "ttl": packet.get("ttl"),
            "ip_flags": packet.get("ip_flags")
        }
        
        if is_fwd:
            self.fwd_packets.append(pkt_info)
        else:
            self.bwd_packets.append(pkt_info)
            
        # Parse TLS details if available
        tls_info = packet.get("tls_info")
        if tls_info:
            if tls_info["type"] == "ClientHello":
                self.tls_version = tls_info.get("tls_version")
                self.cipher_suites = tls_info.get("cipher_suites", [])
                self.extensions = tls_info.get("extensions", [])
                self.sni = tls_info.get("sni")
                self.alpn = tls_info.get("alpn", [])
                self.ec_curves = tls_info.get("ec_curves", [])
                self.ec_formats = tls_info.get("ec_formats", [])
            elif tls_info["type"] == "ServerHello":
                self.tls_version_negotiated = tls_info.get("tls_version")
                self.cipher_suite_negotiated = tls_info.get("cipher_suite")

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.last_seen,
            "duration": self.last_seen - self.start_time,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "tls": {
                "version": self.tls_version,
                "cipher_suites": self.cipher_suites,
                "extensions": self.extensions,
                "sni": self.sni,
                "alpn": self.alpn,
                "ec_curves": self.ec_curves,
                "ec_formats": self.ec_formats,
                "version_negotiated": self.tls_version_negotiated,
                "cipher_suite_negotiated": self.cipher_suite_negotiated
            } if (self.tls_version or self.tls_version_negotiated) else None
        }


class FlowBuilder:
    def __init__(self, on_flow_complete: Optional[Callable[[dict], None]] = None):
        self.flow_table: Dict[Tuple, FlowRecord] = {}
        self.on_flow_complete = on_flow_complete
        self.lock = threading.Lock()
        
        # Configuration
        self.active_timeout = 120.0
        self.idle_timeout = 8.0
        
    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> Tuple:
        """
        Produce a normalized 5-tuple key where smaller IP/ports are ordered first.
        """
        if src_ip < dst_ip:
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        elif src_ip > dst_ip:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
        else:
            if src_port < dst_port:
                return (src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol)

    def add_packet(self, raw_pkt: dict) -> Optional[dict]:
        """
        Adds a packet to the appropriate flow and checks timeouts/flags.
        """
        # Parse packet headers and TLS
        pkt = parse_packet_headers(raw_pkt)
        
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        src_port = pkt["src_port"]
        dst_port = pkt["dst_port"]
        protocol = pkt["protocol"]
        timestamp = pkt["timestamp"]
        
        key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        completed_flow = None
        
        with self.lock:
            if key in self.flow_table:
                flow = self.flow_table[key]
                flow.add_packet(pkt)
                
                # Check active timeout
                if timestamp - flow.start_time >= self.active_timeout:
                    completed_flow = self._finalize_flow(key)
                
                # Check TCP FIN / RST for immediate termination
                elif pkt.get("tcp_flags") and any(f in pkt["tcp_flags"] for f in ["F", "R"]):
                    completed_flow = self._finalize_flow(key)
            else:
                flow_id = str(uuid.uuid4())
                flow = FlowRecord(flow_id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
                flow.add_packet(pkt)
                self.flow_table[key] = flow
                
                # Check immediate termination
                if pkt.get("tcp_flags") and any(f in pkt["tcp_flags"] for f in ["F", "R"]):
                    completed_flow = self._finalize_flow(key)
                    
        if completed_flow and self.on_flow_complete:
            self.on_flow_complete(completed_flow)
            
        return completed_flow

    def _finalize_flow(self, key: Tuple) -> dict:
        flow = self.flow_table.pop(key)
        return flow.to_dict()

    def flush_expired_flows(self, current_time: float) -> List[dict]:
        """
        Scans flow table and flushes active/idle expired flows.
        """
        expired = []
        with self.lock:
            keys_to_remove = []
            for key, flow in self.flow_table.items():
                is_idle = (current_time - flow.last_seen >= self.idle_timeout)
                is_active_expired = (current_time - flow.start_time >= self.active_timeout)
                
                if is_idle or is_active_expired:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                flow_dict = self._finalize_flow(key)
                expired.append(flow_dict)
                
        if expired and self.on_flow_complete:
            for flow_dict in expired:
                self.on_flow_complete(flow_dict)
                
        return expired

    def flush_all_flows(self) -> List[dict]:
        """
        Force flush all active flows currently in the flow table (e.g. at the end of PCAP parsing).
        """
        flushed = []
        with self.lock:
            keys = list(self.flow_table.keys())
            for key in keys:
                flushed.append(self._finalize_flow(key))
                
        if flushed and self.on_flow_complete:
            for flow_dict in flushed:
                self.on_flow_complete(flow_dict)
                
        return flushed

    def get_active_flows(self) -> List[dict]:
        with self.lock:
            return [flow.to_dict() for flow in self.flow_table.values()]
