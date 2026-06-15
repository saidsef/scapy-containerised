#!/usr/bin/env python3
"""Build a directed graph of who initiates TCP connections to whom.
Sniffs SYNs for a window and aggregates by (src, dst, dport).

Usage:  python3 /app/scripts/discovery/conn_graph.py eth0
        python3 /app/scripts/discovery/conn_graph.py eth0 60
        python3 /app/scripts/discovery/conn_graph.py eth0 60 'not net 10.0.0.0/8'
"""
import sys
from collections import defaultdict
from scapy.all import sniff, IP, TCP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
bpf_extra = sys.argv[3] if len(sys.argv) > 3 else ""

bpf = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
if bpf_extra:
    bpf = f"({bpf}) and ({bpf_extra})"

edges = defaultdict(int)
sources = set()


def record(p):
    if IP not in p or TCP not in p:
        return
    src, dst = p[IP].src, p[IP].dst
    dport = int(p[TCP].dport)
    edges[(src, dst, dport)] += 1
    sources.add(src)


print(f"capturing SYNs on {iface} for {timeout}s — Ctrl-C to stop early")
try:
    sniff(iface=iface, filter=bpf, timeout=timeout, prn=record, store=False)
except KeyboardInterrupt:
    pass

print(f"{len(sources)} distinct sources observed\n")
header = f"  {'src':<16} {'dst':<16} {'dport':>6} {'count':>6}"
print(header)

rows = sorted(edges.items(), key=lambda kv: kv[1], reverse=True)
for (src, dst, dport), count in rows:
    print(f"  {src:<16} -> {dst:<16} {dport:>6} {count:>6}")

by_src = defaultdict(set)
for (src, dst, dport) in edges:
    by_src[src].add((dst, dport))
print()
for src, dests in sorted(by_src.items()):
    print(f"{len(dests)} distinct destinations from {src} over {timeout}s")
