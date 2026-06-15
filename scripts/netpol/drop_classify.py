#!/usr/bin/env python3
"""Watch a TCP flow between two endpoints for a window of seconds and
classify which direction is broken and at what layer. Useful when you
can't actively probe and need to diagnose what the real application is
doing.

Usage:  python3 /app/scripts/netpol/drop_classify.py 10.244.1.5 10.244.2.7 8080
        python3 /app/scripts/netpol/drop_classify.py 10.244.1.5 10.244.2.7 8080 60
"""
import sys
from scapy.all import sniff, IP, TCP

if len(sys.argv) < 4:
    print(__doc__)
    sys.exit(2)

src = sys.argv[1]
dst = sys.argv[2]
dport = int(sys.argv[3])
timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 20

state = {
    "syn_from_src": 0,
    "synack_from_dst": 0,
    "rst_from_dst": 0,
    "total": 0,
}


def track(p):
    if not p.haslayer(IP) or not p.haslayer(TCP):
        return
    state["total"] += 1
    ip = p[IP]
    tcp = p[TCP]
    flags = int(tcp.flags)
    syn = flags & 0x02
    ack = flags & 0x10
    rst = flags & 0x04
    if ip.src == src and ip.dst == dst and tcp.dport == dport:
        if syn and not ack:
            state["syn_from_src"] += 1
    if ip.src == dst and ip.dst == src and tcp.sport == dport:
        if syn and ack:
            state["synack_from_dst"] += 1
        if rst:
            state["rst_from_dst"] += 1


bpf = f"host {src} and host {dst} and tcp"
print(f"sniffing '{bpf}' on any for {timeout}s ...")
sniff(iface="any", filter=bpf, prn=track, store=False, timeout=timeout)

s = state["syn_from_src"]
sa = state["synack_from_dst"]
rs = state["rst_from_dst"]
total = state["total"]

if s == 0:
    verdict = f"src never sent (0 SYN from src, {total} pkts)"
elif sa > 0:
    verdict = (f"bidirectional ok (SYN from src, SYN/ACK from dst, "
               f"{total} pkts total)")
elif rs > 0:
    verdict = (f"dst refused (SYN from src, RST from dst, "
               f"{total} pkts)")
else:
    verdict = (f"src->dst broken, no response from dst "
               f"(SYN seen, no SYN/ACK, {total} pkts)")

print(verdict)
