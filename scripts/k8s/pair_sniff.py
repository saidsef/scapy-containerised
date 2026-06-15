#!/usr/bin/env python3
"""Watch traffic between two specific IPs. Run from a Scapy pod with
hostNetwork=true on the same node as the source.

What you see tells you who's dropping:
  SYN out, no SYN/ACK, no ICMP   -> NetworkPolicy or CNI dropping silently
  SYN out, RST/ACK back          -> dest app refused
  SYN out, ICMP unreachable      -> kube-proxy / iptables rejected
  No SYN at all from source      -> app never made the call

Usage:  python3 /app/scripts/k8s/pair_sniff.py 10.244.1.5 10.244.2.7
        python3 /app/scripts/k8s/pair_sniff.py 10.244.1.5 10.244.2.7 any 30
"""
import sys
from scapy.all import sniff, IP, TCP, ICMP

src = sys.argv[1]
dst = sys.argv[2]
iface = sys.argv[3] if len(sys.argv) > 3 else "any"
timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 30


def describe(p):
    if not p.haslayer(IP):
        return p.summary()
    if p.haslayer(TCP):
        return f"{p[IP].src} -> {p[IP].dst}  TCP {p[TCP].sport}->{p[TCP].dport}  flags={p[TCP].flags}"
    if p.haslayer(ICMP):
        return f"{p[IP].src} -> {p[IP].dst}  ICMP type={p[ICMP].type} code={p[ICMP].code}"
    return p.summary()


bpf = f"host {src} and host {dst}"
print(f"sniffing '{bpf}' on {iface} for {timeout}s ...")
sniff(iface=iface, filter=bpf,
      prn=lambda p: print(describe(p)),
      store=False, timeout=timeout)
