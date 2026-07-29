import sqlite3
import os
import json
import logging
import asyncio
from typing import List, Dict, Optional

logger = logging.getLogger("zenith.api.database")
DB_PATH = "data/flows.db"

def init_db_sync():
    """
    Initialize the database, creating the flows table and indexes.
    """
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS flows (
        flow_id TEXT PRIMARY KEY,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        timestamp REAL,
        duration REAL,
        bytes_sent INTEGER,
        bytes_received INTEGER,
        total_packets INTEGER,
        classification TEXT,
        confidence REAL,
        risk_score INTEGER,
        severity TEXT,
        sni TEXT,
        ja3_hash TEXT,
        raw_json TEXT
    )
    """)
    
    # Create indexes for rapid search sorting
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_risk ON flows(risk_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_severity ON flows(severity)")
    
    conn.commit()
    conn.close()
    logger.info("SQLite database initialized successfully.")

async def init_db():
    await asyncio.to_thread(init_db_sync)

def insert_flow_sync(flow_dict: dict):
    """
    Write or replace a flow record.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT OR REPLACE INTO flows (
        flow_id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp, duration,
        bytes_sent, bytes_received, total_packets, classification, confidence,
        risk_score, severity, sni, ja3_hash, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        flow_dict.get("flow_id"),
        flow_dict.get("src_ip"),
        flow_dict.get("dst_ip"),
        flow_dict.get("src_port"),
        flow_dict.get("dst_port"),
        flow_dict.get("protocol"),
        flow_dict.get("timestamp"),
        flow_dict.get("flow_duration"),
        flow_dict.get("bytes_sent"),
        flow_dict.get("bytes_received"),
        flow_dict.get("total_packets"),
        flow_dict.get("classification"),
        flow_dict.get("confidence"),
        flow_dict.get("risk_score"),
        flow_dict.get("severity"),
        flow_dict.get("sni"),
        flow_dict.get("ja3_hash"),
        json.dumps(flow_dict)
    ))
    
    conn.commit()
    conn.close()

async def insert_flow(flow_dict: dict):
    await asyncio.to_thread(insert_flow_sync, flow_dict)

def insert_flows_batch_sync(flows_list: List[dict]):
    if not flows_list:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("BEGIN TRANSACTION")
    for flow_dict in flows_list:
        cursor.execute("""
        INSERT OR REPLACE INTO flows (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp, duration,
            bytes_sent, bytes_received, total_packets, classification, confidence,
            risk_score, severity, sni, ja3_hash, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow_dict.get("flow_id"),
            flow_dict.get("src_ip"),
            flow_dict.get("dst_ip"),
            flow_dict.get("src_port"),
            flow_dict.get("dst_port"),
            flow_dict.get("protocol"),
            flow_dict.get("timestamp"),
            flow_dict.get("flow_duration"),
            flow_dict.get("bytes_sent"),
            flow_dict.get("bytes_received"),
            flow_dict.get("total_packets"),
            flow_dict.get("classification"),
            flow_dict.get("confidence"),
            flow_dict.get("risk_score"),
            flow_dict.get("severity"),
            flow_dict.get("sni"),
            flow_dict.get("ja3_hash"),
            json.dumps(flow_dict)
        ))
    conn.commit()
    conn.close()

async def insert_flows_batch(flows_list: List[dict]):
    await asyncio.to_thread(insert_flows_batch_sync, flows_list)

def get_flows_sync(limit: int = 1000) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    res = []
    for row in rows:
        d = dict(row)
        d["prediction"] = d.get("classification")
        res.append(d)
    return res

async def get_flows(limit: int = 1000) -> List[dict]:
    return await asyncio.to_thread(get_flows_sync, limit)

def get_flow_sync(flow_id: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM flows WHERE flow_id = ?", (flow_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        row_dict = dict(row)
        row_dict["prediction"] = row_dict.get("classification")
        if row_dict.get("raw_json"):
            try:
                full_json = json.loads(row_dict["raw_json"])
                full_json["prediction"] = full_json.get("classification")
                return full_json
            except Exception:
                pass
        return row_dict
    return None

async def get_flow(flow_id: str) -> Optional[dict]:
    return await asyncio.to_thread(get_flow_sync, flow_id)

def get_alerts_sync(limit: int = 1000) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM flows WHERE classification = 'Threat' ORDER BY risk_score DESC, timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    res = []
    for row in rows:
        d = dict(row)
        d["prediction"] = d.get("classification")
        res.append(d)
    return res

async def get_alerts(limit: int = 1000) -> List[dict]:
    return await asyncio.to_thread(get_alerts_sync, limit)

def clear_database_sync():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM flows")
    conn.commit()
    conn.close()

async def clear_database():
    await asyncio.to_thread(clear_database_sync)

def update_flow_status_sync(flow_id: str, classification: str, severity: str, risk_score: int, attack_category: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT raw_json FROM flows WHERE flow_id = ?", (flow_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
        
    raw_json_str = row[0]
    new_raw_json = None
    if raw_json_str:
        try:
            flow_dict = json.loads(raw_json_str)
            flow_dict["classification"] = classification
            flow_dict["severity"] = severity
            flow_dict["risk_score"] = risk_score
            flow_dict["attack_category"] = attack_category
            new_raw_json = json.dumps(flow_dict)
        except Exception:
            new_raw_json = raw_json_str
            
    cursor.execute("""
    UPDATE flows 
    SET classification = ?, severity = ?, risk_score = ?, raw_json = ? 
    WHERE flow_id = ?
    """, (classification, severity, risk_score, new_raw_json, flow_id))
    
    conn.commit()
    conn.close()
    return True

async def update_flow_status(flow_id: str, classification: str, severity: str, risk_score: int, attack_category: str) -> bool:
    return await asyncio.to_thread(update_flow_status_sync, flow_id, classification, severity, risk_score, attack_category)
