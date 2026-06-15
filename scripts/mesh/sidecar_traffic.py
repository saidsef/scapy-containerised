#!/usr/bin/env python3
"""Watch app <-> sidecar conversation on loopback. Distinguishes "app
never called" from "sidecar dropped" from "sidecar rejected after
accept". Default ports are Istio's 15001 (out) and 15006 (in); pass a
comma-separated list as the third arg for Linkerd (4140,4143) or other
intercept ports.

Usage:  python3 /app/scripts/mesh/sidecar_traffic.py
        python3 /app/scripts/mesh/sidecar_traffic.py lo 30
        python3 /app/scripts/mesh/sidecar_traffic.py lo 60 4140,4143
"""
import sys
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
if len(sys.argv) > 3:
    sidecar_ports = [int(p) for p in sys.argv[3].split(",") if p.strip()]
else:
    sidecar_ports = [15001, 15006]

bpf = " or ".join(f"tcp port {p}" for p in sidecar_ports)

stats = {
    "app_syn": 0,
    "sidecar_synack": 0,
    "rst": 0,
    "fin": 0,
    "app_to_sidecar": 0,
    "sidecar_to_app": 0,
    "sidecar_to_external": 0,
}
syn_seen = defaultdict(int)
synack_seen = defaultdict(int)


def direction(p):
    sport, dport = p[TCP].sport, p[TCP].dport
    if dport in sidecar_ports:
        return "app->sidecar"
    if sport in sidecar_ports:
        return "sidecar->app"
    return "sidecar->external"


def flag_str(flags):
    names = []
    f = int(flags)
    if f & 0x02:
        names.append("S")
    if f & 0x10:
        names.append("A")
    if f & 0x01:
        names.append("F")
    if f & 0x04:
        names.append("R")
    if f & 0x08:
        names.append("P")
    return "".join(names) or "-"


def record(p):
    if IP not in p or TCP not in p:
        return
    tcp = p[TCP]
    flags = int(tcp.flags)
    payload_len = len(p[Raw].load) if Raw in p else 0
    d = direction(p)
    stats[d.replace("->", "_to_")] += 1

    sym_mask = flags & 0x17
    if sym_mask == 0x02 and d == "app->sidecar":
        stats["app_syn"] += 1
        syn_seen[(p[IP].src, tcp.sport, p[IP].dst, tcp.dport)] += 1
    elif sym_mask == 0x12 and d == "sidecar->app":
        stats["sidecar_synack"] += 1
        synack_seen[(p[IP].dst, tcp.dport, p[IP].src, tcp.sport)] += 1
    if flags & 0x04:
        stats["rst"] += 1
    if flags & 0x01:
        stats["fin"] += 1

    print(f"  {d:>20}  {p[IP].src}:{tcp.sport} -> {p[IP].dst}:{tcp.dport}  "
          f"flags={flag_str(flags)}  len={payload_len}")


print(f"capturing {bpf!r} on {iface} for {timeout}s "
      f"(sidecar ports: {sidecar_ports}) — Ctrl-C to stop early")
try:
    sniff(iface=iface, filter=bpf, timeout=timeout, prn=record, store=False)
except KeyboardInterrupt:
    pass

silent_drops = 0
for key, n in syn_seen.items():
    if synack_seen.get(key, 0) == 0:
        silent_drops += n

print()
print("summary")
print(f"  app -> sidecar packets:     {stats['app_to_sidecar']}")
print(f"  sidecar -> app packets:     {stats['sidecar_to_app']}")
print(f"  sidecar -> external packets:{stats['sidecar_to_external']}")
print(f"  app SYNs to sidecar:        {stats['app_syn']}")
print(f"  SYN/ACKs back from sidecar: {stats['sidecar_synack']}")
print(f"  RSTs observed:              {stats['rst']}")
print(f"  FINs observed:              {stats['fin']}")
print(f"  app SYNs with no SYN/ACK:   {silent_drops}")
if stats["app_syn"] == 0:
    print("  diagnosis: no traffic from app to sidecar — app isn't calling, "
          "or iptables redirect chain is missing")
elif silent_drops > 0 and stats["sidecar_synack"] == 0:
    print("  diagnosis: sidecar is not accepting connections — proxy may be "
          "down, mis-listening, or blocked by netpol")
elif stats["rst"] > 0 and stats["sidecar_synack"] > 0:
    print("  diagnosis: sidecar accepts then rejects — look at upstream "
          "side (UF/NR/UH in Envoy access log)")
