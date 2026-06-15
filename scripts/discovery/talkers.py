#!/usr/bin/env python3
"""Top talkers by bytes. Aggregates by endpoint pair regardless of direction
so reply traffic folds into the same row as the request.

Usage:  python3 /app/scripts/discovery/talkers.py eth0
        python3 /app/scripts/discovery/talkers.py eth0 60
        python3 /app/scripts/discovery/talkers.py eth0 60 20
"""
import sys
from collections import defaultdict
from scapy.all import sniff, IP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 10

pairs = defaultdict(lambda: {"bytes": 0, "pkts": 0})


def pair_key(a, b):
    return (a, b) if a <= b else (b, a)


def record(p):
    if IP not in p:
        return
    key = pair_key(p[IP].src, p[IP].dst)
    pairs[key]["bytes"] += len(p)
    pairs[key]["pkts"] += 1


print(f"capturing on {iface} for {timeout}s — Ctrl-C to stop early")
try:
    sniff(iface=iface, timeout=timeout, prn=record, store=False)
except KeyboardInterrupt:
    pass

rows = sorted(pairs.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:top_n]
header = f"  {'bytes':>12} {'pkts':>8}   pair"
print(header)
for (a, b), s in rows:
    bytes_fmt = f"{s['bytes']:,}"
    pkts_fmt = f"{s['pkts']:,}"
    print(f"  {bytes_fmt:>12} {pkts_fmt:>8}   {a}  <->  {b}")

print(f"\n{len(pairs)} distinct pairs over {timeout}s on {iface}")
