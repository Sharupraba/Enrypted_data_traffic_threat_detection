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

@router.get("/analytics/stats")
async def fetch_analytics_stats():
    """
    Fetch consolidated database stats for dashboard charting.
    """
    return await asyncio.to_thread(get_analytics_stats_sync)
