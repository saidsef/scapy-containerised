#!/usr/bin/env python3
"""Naive TCP stream reassembly via PacketList.sessions(). Doesn't
reorder by sequence or handle retransmits — Wireshark "Follow TCP
Stream" is the real answer. Good enough for plaintext-protocol
triage from the ttyd prompt.

Usage:  python3 /app/scripts/sniffing/tcp_sessions.py eth0 80 500
"""
import sys
from scapy.all import sniff, TCP, Raw

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
count = int(sys.argv[3]) if len(sys.argv) > 3 else 500

pkts = sniff(iface=iface, filter=f"tcp port {port}", count=count, timeout=60)
for key, stream in pkts.sessions().items():
    payload = b"".join(bytes(p[TCP].payload) for p in stream
                       if TCP in p and Raw in p)
    if not payload:
        continue
    print(key)
    print(payload[:300])
    print("-" * 60)
