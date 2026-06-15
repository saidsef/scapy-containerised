#!/usr/bin/env python3
"""Extract SNI from TLS ClientHello — answers "which hosts is this pod
calling over HTTPS?" without breaking TLS.

Usage:  python3 /app/scripts/sniffing/tls_sni.py eth0
        python3 /app/scripts/sniffing/tls_sni.py eth0 200
"""
import sys
from scapy.all import sniff, load_layer, IP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0

load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello


def sni(p):
    if not p.haslayer(TLSClientHello):
        return
    for ext in p[TLSClientHello].ext or []:
        if getattr(ext, "type", None) == 0 and getattr(ext, "servernames", None):
            print(p[IP].dst, "->",
                  ext.servernames[0].servername.decode(errors="replace"))


sniff(iface=iface, filter="tcp port 443",
      prn=sni, store=False, count=count)
