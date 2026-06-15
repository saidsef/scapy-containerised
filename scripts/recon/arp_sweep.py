#!/usr/bin/env python3
"""ARP sweep a local subnet.

Usage:  python3 /app/scripts/recon/arp_sweep.py 10.0.0.0/24
"""
import sys
from scapy.all import arping, Ether

subnet = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.0/24"
ans, _ = arping(subnet, verbose=0)

print(f"{'IP':<16} {'MAC':<18}")
for _, r in ans:
    print(f"{r.psrc:<16} {r[Ether].src:<18}")
print(f"\n{len(ans)} hosts answered ARP on {subnet}")
