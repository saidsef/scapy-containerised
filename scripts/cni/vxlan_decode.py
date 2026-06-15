#!/usr/bin/env python3
"""Decode VXLAN (UDP 4789) and print outer nodes, VNI, and inner 5-tuple.
The signal for "is encapsulation working and what's actually inside it".

Usage:  python3 /app/scripts/cni/vxlan_decode.py eth0
        python3 /app/scripts/cni/vxlan_decode.py eth0 200
        python3 /app/scripts/cni/vxlan_decode.py eth0 0 4789
"""
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.vxlan import VXLAN

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0
port = int(sys.argv[3]) if len(sys.argv) > 3 else 4789


def flag_str(tcp):
    names = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
             0x10: "A", 0x20: "U", 0x40: "E", 0x80: "C"}
    f = int(tcp.flags)
    return "".join(n for bit, n in names.items() if f & bit) or "-"


def show(p):
    if VXLAN not in p or IP not in p:
        return
    outer = p[IP]
    vni = p[VXLAN].vni
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
