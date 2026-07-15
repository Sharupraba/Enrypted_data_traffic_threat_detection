import struct
import logging
from typing import Optional

logger = logging.getLogger("zenith.parsing.packet")

def parse_tls_clienthello(data: bytes) -> Optional[dict]:
    """
    Parses TLS ClientHello from raw TCP payload bytes.
    Returns ClientHello details or None if not matching or malformed.
    """
    try:
        # Check if record starts with Handshake (0x16) and TLS Version (0x03 0x0X)
        if len(data) < 5 or data[0] != 0x16 or data[1] != 0x03:
            return None
        
        record_len = struct.unpack("!H", data[3:5])[0]
        handshake_data = data[5 : 5 + record_len]
        
        if len(handshake_data) < 4 or handshake_data[0] != 0x01: # ClientHello Handshake Type = 1
            return None
            
        offset = 4 # Skip type (1) and length (3)
        client_version = struct.unpack("!H", handshake_data[offset:offset+2])[0]
        offset += 2
        offset += 32 # Skip Random (32 bytes)
        
        # Session ID
        session_id_len = handshake_data[offset]
        offset += 1 + session_id_len
        
        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", handshake_data[offset:offset+2])[0]
        offset += 2
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            val = struct.unpack("!H", handshake_data[offset+i : offset+i+2])[0]
            # Ignore GREASE ciphers (0x0a0a, 0x1a1a, etc.)
            if (val & 0x0f0f) != 0x0a0a:
                cipher_suites.append(val)
        offset += cipher_suites_len
        
        # Compression Methods
        comp_len = handshake_data[offset]
        offset += 1 + comp_len
        
        # Extensions
        extensions = []
        sni = None
        alpn = []
        ec_curves = []
        ec_formats = []
        
        if offset + 2 <= len(handshake_data):
            ext_len_total = struct.unpack("!H", handshake_data[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_len_total
            
            while offset < ext_end and offset + 4 <= len(handshake_data):
                ext_type = struct.unpack("!H", handshake_data[offset:offset+2])[0]
                ext_len = struct.unpack("!H", handshake_data[offset+2:offset+4])[0]
                offset += 4
                
                # Ignore GREASE extensions
                if (ext_type & 0x0f0f) != 0x0a0a:
                    extensions.append(ext_type)
                
                ext_data = handshake_data[offset : offset + ext_len]
                offset += ext_len
                
                # Parse SNI (extension 0)
                if ext_type == 0:
                    try:
                        if len(ext_data) > 5 and ext_data[2] == 0:
                            name_len = struct.unpack("!H", ext_data[3:5])[0]
                            sni = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                
                # Parse Supported Groups / Elliptic Curves (extension 10)
                elif ext_type == 10:
                    try:
                        curves_len = struct.unpack("!H", ext_data[0:2])[0]
                        for i in range(2, curves_len + 2, 2):
                            val = struct.unpack("!H", ext_data[i:i+2])[0]
                            if (val & 0x0f0f) != 0x0a0a:
                                ec_curves.append(val)
                    except Exception:
                        pass
                
                # Parse EC Point Formats (extension 11)
                elif ext_type == 11:
                    try:
                        formats_len = ext_data[0]
                        for i in range(1, formats_len + 1):
                            ec_formats.append(ext_data[i])
                    except Exception:
                        pass
                        
                # Parse ALPN (extension 16)
                elif ext_type == 16:
                    try:
                        alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                        alpn_offset = 2
                        while alpn_offset < alpn_list_len + 2:
                            proto_len = ext_data[alpn_offset]
                            proto = ext_data[alpn_offset+1 : alpn_offset+1+proto_len].decode("utf-8", errors="ignore")
                            alpn.append(proto)
                            alpn_offset += 1 + proto_len
                    except Exception:
                        pass
        
        return {
            "tls_version": f"0x{client_version:04x}",
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "sni": sni,
            "alpn": alpn,
            "ec_curves": ec_curves,
            "ec_formats": ec_formats
        }
    except Exception as e:
        logger.debug(f"Failed to parse TLS ClientHello: {e}")
        return None

def parse_tls_serverhello(data: bytes) -> Optional[dict]:
    """
    Parses TLS ServerHello from raw TCP payload bytes.
    Returns ServerHello details or None if not matching or malformed.
    """
    try:
        if len(data) < 5 or data[0] != 0x16 or data[1] != 0x03:
            return None
        
        record_len = struct.unpack("!H", data[3:5])[0]
        handshake_data = data[5 : 5 + record_len]
        
        if len(handshake_data) < 4 or handshake_data[0] != 0x02: # ServerHello Handshake Type = 2
            return None
            
        offset = 4 # Skip type (1) and length (3)
        server_version = struct.unpack("!H", handshake_data[offset:offset+2])[0]
        offset += 2
        offset += 32 # Skip Random (32 bytes)
        
        session_id_len = handshake_data[offset]
        offset += 1 + session_id_len
        
        selected_cipher = struct.unpack("!H", handshake_data[offset:offset+2])[0]
        offset += 2
        
        # Skip selected compression
        offset += 1
        
        extensions = []
        if offset + 2 <= len(handshake_data):
            ext_len_total = struct.unpack("!H", handshake_data[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_len_total
            
            while offset < ext_end and offset + 4 <= len(handshake_data):
                ext_type = struct.unpack("!H", handshake_data[offset:offset+2])[0]
                ext_len = struct.unpack("!H", handshake_data[offset+2:offset+4])[0]
                offset += 4
                
                if (ext_type & 0x0f0f) != 0x0a0a:
                    extensions.append(ext_type)
                offset += ext_len
                
        return {
            "tls_version": f"0x{server_version:04x}",
            "cipher_suite": selected_cipher,
            "extensions": extensions
        }
    except Exception as e:
        logger.debug(f"Failed to parse TLS ServerHello: {e}")
        return None

def parse_packet_headers(pkt_dict: dict) -> dict:
    """
    Refines raw packet details from Ingestion Layer.
    Dissects TLS ClientHello or ServerHello if tls_raw bytes are present.
    """
    tls_info = None
    tls_raw = pkt_dict.get("tls_raw")
    
    if tls_raw:
        # Check if ClientHello (Handshake type 1) or ServerHello (Handshake type 2)
        if len(tls_raw) > 5 and tls_raw[0] == 0x16:
            # 5th byte is handshake type
            handshake_type = tls_raw[5]
            if handshake_type == 1:
                client_hello = parse_tls_clienthello(tls_raw)
                if client_hello:
                    tls_info = {
                        "type": "ClientHello",
                        **client_hello
                    }
            elif handshake_type == 2:
                server_hello = parse_tls_serverhello(tls_raw)
                if server_hello:
                    tls_info = {
                        "type": "ServerHello",
                        **server_hello
                    }
                    
    # Return copy with optional tls metadata attached
    res = dict(pkt_dict)
    res["tls_info"] = tls_info
    return res
