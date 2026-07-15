import hashlib
import ipaddress
from typing import Optional

# Decimal IDs of common weak TLS cipher suites (RC4, 3DES, Export, Null)
WEAK_CIPHERS = {
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015,
    0x0016, 0x0017, 0x0018, 0x001b, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0080,
    0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a,
    0x008b, 0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094,
    0x0095, 0xc001, 0xc002, 0xc003, 0xc004, 0xc005, 0xc006, 0xc007, 0xc008, 0xc009,
    0xc00a, 0xc00b, 0xc00c, 0xc00d, 0xc00e, 0xc00f, 0xc010, 0xc011, 0xc012, 0xc013,
    0xc014, 0xc015, 0xc016, 0xc017, 0xc018, 0xc019, 0xc01a, 0xc01b, 0xc01c, 0xc01d
}

def extract_tls_features(flow: dict) -> dict:
    """
    Extracts TLS parameters including JA3, JA3S, weak cipher indicators, and certificate risk properties.
    """
    tls = flow.get("tls")
    
    # Defaults
    tls_version = None
    tls_version_risk = 0
    cipher_suite = None
    cipher_is_weak = False
    ja3_hash = None
    ja3s_hash = None
    sni = None
    sni_is_ip = False
    has_sni = False
    alpn = None
    alpn_is_suspicious = False
    tls_extension_count = 0
    cert_self_signed = False
    cert_expired = False
    cert_days_to_expiry = -1
    cert_domain_mismatch = False
    cert_is_short_lived = False
    
    if tls:
        # Client Hello details
        raw_version = tls.get("version")
        if raw_version:
            tls_version = raw_version
            try:
                version_val = int(raw_version, 16)
                if version_val < 0x0303:  # Lower than TLS 1.2 (0x0303)
                    tls_version_risk = 2
                elif version_val == 0x0303:  # TLS 1.2
                    tls_version_risk = 1
                else:  # TLS 1.3 (0x0304)
                    tls_version_risk = 0
            except ValueError:
                tls_version_risk = 1
                
        # Negotiated / Offered ciphers
        cipher_suite_negotiated = tls.get("cipher_suite_negotiated")
        if cipher_suite_negotiated is not None:
            cipher_suite = f"0x{cipher_suite_negotiated:04x}"
            cipher_is_weak = (cipher_suite_negotiated in WEAK_CIPHERS)
        elif tls.get("cipher_suites"):
            first_offered = tls["cipher_suites"][0]
            cipher_suite = f"0x{first_offered:04x}"
            cipher_is_weak = (first_offered in WEAK_CIPHERS)

        # JA3 & JA3S
        ja3_hash = calculate_ja3(tls)
        ja3s_hash = calculate_ja3s(tls)
        
        # SNI details
        sni = tls.get("sni")
        if sni:
            has_sni = True
            try:
                ipaddress.ip_address(sni)
                sni_is_ip = True
            except ValueError:
                sni_is_ip = False
                
        # ALPN details
        alpn_list = tls.get("alpn") or []
        if alpn_list:
            alpn = alpn_list[0]
            dst_port = flow.get("dst_port", 0)
            if dst_port == 443 and alpn not in ["h2", "http/1.1", "grpc"]:
                alpn_is_suspicious = True
                
        tls_extension_count = len(tls.get("extensions") or [])
        
        # Cert details
        cert_self_signed = tls.get("cert_self_signed", False)
        cert_expired = tls.get("cert_expired", False)
        cert_days_to_expiry = tls.get("cert_days_to_expiry", -1)
        cert_domain_mismatch = tls.get("cert_domain_mismatch", False)
        cert_is_short_lived = tls.get("cert_is_short_lived", False)

    return {
        "tls_version": tls_version,
        "tls_version_risk": tls_version_risk,
        "cipher_suite": cipher_suite,
        "cipher_is_weak": cipher_is_weak,
        "ja3_hash": ja3_hash,
        "ja3s_hash": ja3s_hash,
        "sni": sni,
        "sni_is_ip": sni_is_ip,
        "has_sni": has_sni,
        "alpn": alpn,
        "alpn_is_suspicious": alpn_is_suspicious,
        "tls_extension_count": tls_extension_count,
        "cert_self_signed": cert_self_signed,
        "cert_expired": cert_expired,
        "cert_days_to_expiry": cert_days_to_expiry,
        "cert_domain_mismatch": cert_domain_mismatch,
        "cert_is_short_lived": cert_is_short_lived
    }

def calculate_ja3(tls: dict) -> Optional[str]:
    version_str = tls.get("version")
    if not version_str:
        return None
    try:
        version_dec = str(int(version_str, 16))
    except ValueError:
        version_dec = "771"
        
    ciphers = "-".join(str(c) for c in tls.get("cipher_suites", []))
    extensions = "-".join(str(e) for e in tls.get("extensions", []))
    curves = "-".join(str(c) for c in tls.get("ec_curves", []))
    formats = "-".join(str(f) for f in tls.get("ec_formats", []))
    
    ja3_str = f"{version_dec},{ciphers},{extensions},{curves},{formats}"
    return hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

def calculate_ja3s(tls: dict) -> Optional[str]:
    version_str = tls.get("version_negotiated")
    cipher = tls.get("cipher_suite_negotiated")
    if not version_str or cipher is None:
        return None
    try:
        version_dec = str(int(version_str, 16))
    except ValueError:
        version_dec = "771"
        
    extensions = "-".join(str(e) for e in tls.get("extensions", []))
    ja3s_str = f"{version_dec},{cipher},{extensions}"
    return hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()
