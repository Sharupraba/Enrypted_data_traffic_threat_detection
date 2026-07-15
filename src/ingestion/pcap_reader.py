import logging
from typing import Generator
from scapy.all import PcapReader
from .live_capture import scapy_packet_to_dict

logger = logging.getLogger("zenith.ingestion.pcap")

def read_pcap(file_path: str) -> Generator[dict, None, None]:
    """
    Reads a PCAP file and yields header-only packet dictionaries.
    """
    logger.info(f"Reading PCAP file: {file_path}")
    try:
        with PcapReader(file_path) as reader:
            for packet in reader:
                pkt_dict = scapy_packet_to_dict(packet)
                if pkt_dict:
                    yield pkt_dict
    except Exception as e:
        logger.error(f"Error reading PCAP file {file_path}: {e}")
