#!/usr/bin/env python3
"""Decode and print JSON bodies carried in plaintext packet payloads.

Usage:  python3 /app/scripts/traffic.py eth0
        python3 /app/scripts/traffic.py eth0 'tcp port 8080'
"""
import json
import sys
from scapy.all import Raw, sniff

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
bpf = sys.argv[2] if len(sys.argv) > 2 else None


def show(p):
    try:
        print(json.loads(p[Raw].load))
    except (ValueError, UnicodeDecodeError):
        pass  # non-JSON payloads are the common case, not an error


sniff(iface=iface, filter=bpf,
      lfilter=lambda p: p.haslayer(Raw),
      prn=show, store=False, count=0)
