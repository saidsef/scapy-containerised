#!/usr/bin/env python3
"""Passive OS fingerprint by looking at TTL and TCP window in inbound SYNs.
Crude, fast, often good enough to triage.

Usage:  python3 /app/scripts/recon/passive_os.py eth0 50
"""
import sys
from scapy.all import sniff, IP, TCP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 50


def guess(p):
    if not (p.haslayer(IP) and p.haslayer(TCP)):
        return
    ttl, win = p[IP].ttl, p[TCP].window
    if ttl <= 64 and win in (5840, 14600, 29200, 65535):
        hint = "linux"
    elif ttl <= 128 and win in (8192, 64240, 65535):
        hint = "windows"
    elif ttl <= 255:
        hint = "cisco/bsd"
    else:
        hint = "?"
    print(f"{p[IP].src:>15}  ttl={ttl:<3} win={win:<6}  -> {hint}")


sniff(iface=iface,
      lfilter=lambda p: TCP in p and p[TCP].flags == "S",
      prn=guess, count=count)
