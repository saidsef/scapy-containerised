#!/usr/bin/env python3
"""Print a one-line summary per packet. Ctrl-C to stop.

Usage:  python3 /app/scripts/sniffing/live_summary.py eth0
        python3 /app/scripts/sniffing/live_summary.py eth0 'tcp port 443'
"""
import sys
from scapy.all import sniff

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
bpf = sys.argv[2] if len(sys.argv) > 2 else None

sniff(iface=iface, filter=bpf,
      prn=lambda p: print(p.summary()),
      store=False, count=0)
