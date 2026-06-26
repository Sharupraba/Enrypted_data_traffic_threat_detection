"""
extractor.py
Runs NFStream on a PCAP file and returns a DataFrame
of per-flow features mapped to the training feature names.
"""
from pathlib import Path
import pandas as pd
from nfstream import NFStreamer

def extract_features(pcap_path: str | Path) -> pd.DataFrame:
    """
    Extract flow features from a PCAP file using NFStream.

    Returns a DataFrame with:
      - Identity columns: src_ip, dst_ip, src_port, dst_port, protocol
      - TLS metadata: sni, ja3_hash (if available)
      - 30 training features mapped to CICIDS2017 column names
    """
    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,
        splt_analysis=10,
        n_dissections=20,
        active_timeout=120,
        idle_timeout=30,
    )

    records = []
    for flow in streamer:
        duration_s = flow.bidirectional_duration_ms / 1000.0
        fwd_bytes = flow.src2dst_bytes
        bwd_bytes = flow.dst2src_bytes
        total_pkts = flow.bidirectional_packets

        record = {
            # Identity (not used as features — returned for display)
            "src_ip":    flow.src_ip,
            "dst_ip":    flow.dst_ip,
            "src_port":  flow.src_port,
            "dst_port":  flow.dst_port,
            "protocol":  flow.protocol,

            # TLS metadata (bonus — not in training features)
            "sni":       getattr(flow, "requested_server_name", None) or "",
            "ja3_hash":  getattr(flow, "client_fingerprint", None) or "",

            # --- 30 Training Features (CICIDS2017 names) ---
            "Flow Duration":                  duration_s,
            "Total Fwd Packets":              flow.src2dst_packets,
            "Total Backward Packets":         flow.dst2src_packets,
            "Total Length of Fwd Packets":    fwd_bytes,
            "Total Length of Bwd Packets":    bwd_bytes,
            "Fwd Packet Length Mean":         flow.src2dst_mean_ps,
            "Fwd Packet Length Std":          flow.src2dst_stddev_ps,
            "Fwd Packet Length Max":          flow.src2dst_max_ps,
            "Fwd Packet Length Min":          flow.src2dst_min_ps,
            "Bwd Packet Length Mean":         flow.dst2src_mean_ps,
            "Bwd Packet Length Std":          flow.dst2src_stddev_ps,
            "Bwd Packet Length Max":          flow.dst2src_max_ps,
            "Bwd Packet Length Min":          flow.dst2src_min_ps,
            "Flow Bytes/s":                   (fwd_bytes + bwd_bytes) / max(duration_s, 1e-9),
            "Flow Packets/s":                 total_pkts / max(duration_s, 1e-9),
            "Flow IAT Mean":                  flow.bidirectional_mean_piat_ms,
            "Flow IAT Std":                   flow.bidirectional_stddev_piat_ms,
            "Flow IAT Max":                   flow.bidirectional_max_piat_ms,
            "Flow IAT Min":                   flow.bidirectional_min_piat_ms,
            "Fwd IAT Mean":                   flow.src2dst_mean_piat_ms,
            "Fwd IAT Std":                    flow.src2dst_stddev_piat_ms,
            "Fwd IAT Max":                    flow.src2dst_max_piat_ms,
            "Fwd IAT Min":                    flow.src2dst_min_piat_ms,
            "Bwd IAT Mean":                   flow.dst2src_mean_piat_ms,
            "Bwd IAT Std":                    flow.dst2src_stddev_piat_ms,
            "Bwd IAT Max":                    flow.dst2src_max_piat_ms,
            "Bwd IAT Min":                    flow.dst2src_min_piat_ms,
            "Fwd PSH Flags":                  getattr(flow, "src2dst_psh_packets", 0),
            "SYN Flag Count":                 getattr(flow, "src2dst_syn_packets", 0),
            "Down/Up Ratio":                  bwd_bytes / max(fwd_bytes, 1e-9),
        }
        records.append(record)

    return pd.DataFrame(records) if records else pd.DataFrame()
