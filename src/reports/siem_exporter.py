import time
from datetime import datetime, timezone
from typing import List, Dict

def _severity_to_cef_num(severity: str) -> int:
    """
    Maps Zenith text severity levels to CEF numeric scale (0 - 10).
    """
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return 10
    elif sev == "HIGH":
        return 8
    elif sev == "MEDIUM":
        return 5
    elif sev == "LOW":
        return 2
    return 0

def format_cef_event(flow: Dict) -> str:
    """
    Formats a single flow dictionary into Common Event Format (CEF).
    Syntax: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    flow_id = flow.get("flow_id", "UNKNOWN")
    category = flow.get("attack_category", flow.get("classification", "Benign"))
    severity = flow.get("severity", "SAFE")
    cef_sev = _severity_to_cef_num(severity)
    
    src_ip = flow.get("src_ip", "0.0.0.0")
    dst_ip = flow.get("dst_ip", "0.0.0.0")
    src_port = flow.get("src_port", 0)
    dst_port = flow.get("dst_port", 0)
    protocol = flow.get("protocol", "TCP")
    risk_score = flow.get("risk_score", 0)
    anomaly_score = flow.get("anomaly_score", 0.0)
    sni = flow.get("sni", "")
    
    # Extension key-value pairs
    ext_parts = [
        f"src={src_ip}",
        f"dst={dst_ip}",
        f"spt={src_port}",
        f"dpt={dst_port}",
        f"proto={protocol}",
        f"act={'BLOCK' if severity in ['HIGH', 'CRITICAL'] else 'ALLOW'}",
        f"cn1={risk_score}",
        "cn1Label=RiskScore",
        f"cs1={category}",
        "cs1Label=AttackCategory",
        f"cs2={anomaly_score}",
        "cs2Label=ZeroDayAnomalyScore"
    ]
    if sni:
        ext_parts.append(f"request={sni}")
        
    extension_str = " ".join(ext_parts)
    
    return f"CEF:0|ThreatDetectionEngine|ThreatDetector|2.0|{flow_id}|{category} Threat Detected|{cef_sev}|{extension_str}"

def format_syslog_event(flow: Dict) -> str:
    """
    Formats a single flow dictionary into RFC 5424 Syslog standard format.
    """
    ts = flow.get("timestamp")
    if ts:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        dt = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
    category = flow.get("attack_category", flow.get("classification", "Benign"))
    severity = flow.get("severity", "SAFE")
    src_ip = flow.get("src_ip", "0.0.0.0")
    dst_ip = flow.get("dst_ip", "0.0.0.0")
    src_port = flow.get("src_port", 0)
    dst_port = flow.get("dst_port", 0)
    risk_score = flow.get("risk_score", 0)
    anomaly_score = flow.get("anomaly_score", 0.0)
    
    sd_element = f'[threat@48811 src_ip="{src_ip}" dst_ip="{dst_ip}" src_port="{src_port}" dst_port="{dst_port}" severity="{severity}" category="{category}" risk_score="{risk_score}" anomaly_score="{anomaly_score}"]'
    msg = f"{category} network threat detected from {src_ip}:{src_port} targeting {dst_ip}:{dst_port}."
    
    # Priority 14 = Facility 1 (user-level), Severity 6 (info) or 3 (error)
    pri = 11 if severity in ["HIGH", "CRITICAL"] else 14
    return f"<{pri}>1 {dt} threat-detector engine - - - {sd_element} {msg}"

def generate_cef_export(flows: List[Dict]) -> str:
    """
    Generates a full CEF file string for a list of flow records.
    """
    lines = [format_cef_event(flow) for flow in flows]
    return "\n".join(lines)

def generate_syslog_export(flows: List[Dict]) -> str:
    """
    Generates a full Syslog file string for a list of flow records.
    """
    lines = [format_syslog_event(flow) for flow in flows]
    return "\n".join(lines)
