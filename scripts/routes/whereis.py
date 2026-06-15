#!/usr/bin/env python3
"""For a given IP, show what Scapy thinks the route is, what ARP says
for the next hop, and whether the host actually answers ICMP.

Usage:  python3 /app/scripts/routes/whereis.py 8.8.8.8
        python3 /app/scripts/routes/whereis.py 10.0.0.1
"""
import sys
from scapy.all import conf, getmacbyip, sr1, IP, ICMP

ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"

iface, src, gw = conf.route.route(ip)
print(f"{ip}: via {iface} src {src} gw {gw}")

mac = getmacbyip(gw) if gw != "0.0.0.0" else "(direct, no gw)"
print(f"  next-hop MAC: {mac}")

r = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
print(f"  ping: {'OK (' + r[IP].src + ')' if r else 'no reply'}")
