import sqlite3
import asyncio
from fastapi import APIRouter
from src.api.database import DB_PATH

router = APIRouter()

def get_analytics_stats_sync() -> dict:
    """
    Synchronous helper to run aggregate dashboard stats against flows database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Total flows and threats count
    cursor.execute("SELECT COUNT(*), SUM(CASE WHEN classification='Threat' THEN 1 ELSE 0 END) FROM flows")
    total_flows, total_threats = cursor.fetchone()
    total_flows = total_flows or 0
    total_threats = total_threats or 0
    
    # 2. Total bytes volume
    cursor.execute("SELECT SUM(bytes_sent + bytes_received) FROM flows")
    total_bytes = cursor.fetchone()[0] or 0
    
    # 3. Severity breakdown
    cursor.execute("SELECT severity, COUNT(*) FROM flows GROUP BY severity")
    severity_rows = cursor.fetchall()
    severity_breakdown = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for row in severity_rows:
        if row[0] in severity_breakdown:
            severity_breakdown[row[0]] = row[1]
            
    # 4. Protocol breakdown
    cursor.execute("SELECT protocol, COUNT(*) FROM flows GROUP BY protocol")
    protocol_rows = cursor.fetchall()
    protocol_breakdown = {"TCP": 0, "UDP": 0}
    for row in protocol_rows:
        if row[0] in protocol_breakdown:
            protocol_breakdown[row[0]] = row[1]
        else:
            protocol_breakdown[row[0]] = row[1]
        
    # 5. Top 5 suspicious destination IPs
    cursor.execute("""
        SELECT dst_ip, COUNT(*) as cnt 
        FROM flows 
        WHERE classification = 'Threat' 
        GROUP BY dst_ip 
        ORDER BY cnt DESC 
        LIMIT 5
    """)
    top_suspect_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_flows": total_flows,
        "total_threats": total_threats,
        "total_bytes": total_bytes,
        "severity_breakdown": severity_breakdown,
        "protocol_breakdown": protocol_breakdown,
        "top_suspect_ips": top_suspect_ips
    }

from src.enrichment.ip_reputation import check_ip_reputation
from src.enrichment.domain_reputation import check_domain_reputation
from src.enrichment.ja3_lookup import lookup_ja3

@router.get("/analytics/stats")
async def fetch_analytics_stats():
    """
    Fetch consolidated database stats for dashboard charting.
    """
    return await asyncio.to_thread(get_analytics_stats_sync)

@router.get("/intel/lookup")
async def threat_intel_lookup(query: str, query_type: str = "IP"):
    """
    Real-time Threat Intelligence lookup for IP, Domain, or JA3 hashes.
    """
    q_type = query_type.upper()
    if q_type == "IP":
        score, ok = await check_ip_reputation(query)
        is_private = query.startswith(("192.168.", "10.", "172.16.", "127."))
        status = "MALICIOUS" if score > 50 else ("CLEAN" if not is_private else "PRIVATE")
        label = "High-Risk Threat Actor IP" if score > 50 else ("Clean Public Address" if not is_private else "Local Private Subnet")
        details = f"AbuseIPDB / VirusTotal threat score: {score}%." if not is_private else "IP is inside local RFC1918 private network subnet."
        return {
            "query": query,
            "type": "IP",
            "status": status,
            "label": label,
            "abuse_score": score,
            "vt_percentage": score,
            "details": details
        }
    elif q_type == "DOMAIN":
        score, ok = await check_domain_reputation(query)
        is_malicious = score > 30
        status = "MALICIOUS" if is_malicious else "CLEAN"
        label = "High-Risk Malicious Host Domain (DGA / Phishing)" if is_malicious else "Standard Registered Domain Name"
        details = f"Threat intelligence & DGA entropy risk score: {score}%. Domain exhibits characteristics associated with malware hosting or DGA fast-flux algorithms." if is_malicious else "Domain registered clean with normal character entropy."
        return {
            "query": query,
            "type": "DOMAIN",
            "status": status,
            "label": label,
            "vt_percentage": score,
            "details": details
        }
    else:
        ja3_res = lookup_ja3(query)
        if ja3_res["ja3_match"]:
            return {
                "query": query,
                "type": "JA3",
                "status": "MALICIOUS",
                "label": ja3_res["ja3_threat_label"],
                "details": "Critical Signature Match: ClientHello fingerprinted as an active command-and-control connection tool."
            }
        else:
            return {
                "query": query,
                "type": "JA3",
                "status": "CLEAN",
                "label": "Standard Web Client Signature",
                "details": "Unknown signature. Corresponds to common web browser footprint."
            }
