#!/usr/bin/env python3
"""Hex-dump payloads on a TCP port. Useful when reverse-engineering an
unknown binary protocol.

Usage:  python3 /app/scripts/recon/raw_dump.py 4000
        python3 /app/scripts/recon/raw_dump.py 4000 50
"""
import sys
from scapy.all import sniff, hexdump, IP, Raw

port = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
count = int(sys.argv[2]) if len(sys.argv) > 2 else 50

pkts = sniff(filter=f"tcp port {port}", count=count, timeout=60)
for p in pkts:
    if Raw in p:
        print(f"\n--- {p[IP].src} -> {p[IP].dst} ({len(p[Raw].load)} bytes) ---")
        hexdump(p[Raw].load)
