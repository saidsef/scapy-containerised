#!/usr/bin/env python3
"""TCP SYN scan against a single host. Tears down the half-open
connections with RST so the target stops waiting.

Usage:  python3 /app/scripts/recon/syn_scan.py 10.0.0.5
        python3 /app/scripts/recon/syn_scan.py 10.0.0.5 22,80,443,8080
"""
import sys
from scapy.all import IP, TCP, sr, send

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
ports = (
    [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2
    else [22, 80, 443, 3306, 5432, 6379, 8080, 9090]
)

ans, _ = sr(IP(dst=target)/TCP(dport=ports, flags="S"), timeout=2, verbose=0)
opened, refused = [], []
for snd, rcv in ans:
    if rcv[TCP].flags == "SA":
        opened.append(rcv.sport)
        send(IP(dst=rcv.src)/TCP(sport=snd.sport, dport=rcv.sport,
                                 flags="R", seq=rcv.ack), verbose=0)
    elif rcv[TCP].flags == "RA":
        refused.append(rcv.sport)

print(f"{target}: open={sorted(opened)} closed={sorted(refused)}")
filtered = sorted(set(ports) - set(opened) - set(refused))
if filtered:
    print(f"          filtered/no-reply={filtered}")
