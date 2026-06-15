#!/usr/bin/env python3
"""Print Method + Host + Path for every plaintext HTTP request seen.

Usage:  python3 /app/scripts/sniffing/http_requests.py eth0
        python3 /app/scripts/sniffing/http_requests.py eth0 100
"""
import sys
from scapy.all import sniff, load_layer

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0 = forever

load_layer("http")


def show(p):
    if p.haslayer("HTTPRequest"):
        r = p["HTTPRequest"]
        print(r.Method.decode(),
              (r.Host or b"").decode() + (r.Path or b"").decode())


sniff(iface=iface, filter="tcp port 80",
      lfilter=lambda p: p.haslayer("HTTPRequest"),
      prn=show, store=False, count=count)
