#!/usr/bin/env python3
"""Decode Geneve (UDP 6081) and print outer nodes, VNI, and inner 5-tuple.
The signal for "is Cilium/OVS encapsulation working and what's inside".

Usage:  python3 /app/scripts/cni/geneve_decode.py eth0
        python3 /app/scripts/cni/geneve_decode.py eth0 200
        python3 /app/scripts/cni/geneve_decode.py eth0 0 6081
"""
import sys
from scapy.all import sniff, load_contrib, IP, TCP, UDP, ICMP

load_contrib("geneve")
from scapy.contrib.geneve import GENEVE

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0
port = int(sys.argv[3]) if len(sys.argv) > 3 else 6081


def flag_str(tcp):
    names = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
             0x10: "A", 0x20: "U", 0x40: "E", 0x80: "C"}
    f = int(tcp.flags)
    return "".join(n for bit, n in names.items() if f & bit) or "-"


def show(p):
    if GENEVE not in p or IP not in p:
        return
    outer = p[IP]
    vni = p[GENEVE].vni
    inner = p.getlayer(IP, 2)
    if inner is None:
        print(f"underlay {outer.src} -> {outer.dst}  vni={vni}  inner (no IP)")
        return
    line = f"underlay {outer.src} -> {outer.dst}  vni={vni}  inner {inner.src} -> {inner.dst}"
    if TCP in inner:
        t = inner[TCP]
        line += f"  TCP {t.sport} -> {t.dport}  [{flag_str(t)}]"
    elif UDP in inner:
        u = inner[UDP]
        line += f"  UDP {u.sport} -> {u.dport}"
    elif ICMP in inner:
        line += f"  ICMP type={inner[ICMP].type}"
    else:
        line += f"  proto={inner.proto}"
    print(line)


bpf = f"udp port {port}"
print(f"sniffing {bpf!r} on {iface}, count={count or 'forever'} — Ctrl-C to stop")
try:
    sniff(iface=iface, filter=bpf, prn=show, store=False, count=count)
except KeyboardInterrupt:
    pass
