#!/usr/bin/env python3
"""ICMP sweep across an L3 boundary. ARP can't cross routers.

Usage:  python3 /app/scripts/recon/icmp_sweep.py 10.0.0.0/24
"""
import sys
from scapy.all import IP, ICMP, sr

subnet = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.0/24"
ans, _ = sr(IP(dst=subnet)/ICMP(), timeout=2, verbose=0)

for _, r in ans:
    print(f"{r[IP].src} is up")
print(f"\n{len(ans)} hosts responded to ICMP echo")
