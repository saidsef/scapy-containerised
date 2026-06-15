#!/usr/bin/env python3
"""Probe path MTU with DF-bit ICMP echoes. If small pings work and big
ones don't, you're hitting a tunnel MTU (VXLAN/IPIP/WireGuard).

Usage:  python3 /app/scripts/k8s/pmtu.py 10.0.0.5
"""
import sys
from scapy.all import sr1, IP, ICMP

target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"

for size in (1500, 1450, 1400, 1280, 1024, 576):
    payload = "X" * (size - 28)            # 20 IP + 8 ICMP header
    r = sr1(IP(dst=target, flags="DF")/ICMP()/payload, timeout=2, verbose=0)
    print(f"{size:>4} bytes -> {'ok' if r else 'no reply (likely PMTU)'}")
