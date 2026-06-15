#!/usr/bin/env python3
"""Send TCP SYN probes and classify each response into one of four
outcomes: open (SYN/ACK), refused (RST), rejected (ICMP unreachable),
or silently dropped (no reply within timeout). Silent drops are the
fingerprint of a NetworkPolicy or CNI blackhole.

Usage:  python3 /app/scripts/netpol/probe.py 10.244.2.7 8080
        python3 /app/scripts/netpol/probe.py 10.244.2.7 8080 5
        python3 /app/scripts/netpol/probe.py 10.244.2.7 8080 3 1
"""
import sys
from collections import Counter
from scapy.all import sr1, IP, TCP, ICMP

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(2)

target = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3]) if len(sys.argv) > 3 else 3
timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 2


def classify(reply):
    if reply is None:
        return "silently dropped"
    if reply.haslayer(TCP):
        flags = reply[TCP].flags
        if flags & 0x12 == 0x12:        # SYN+ACK
            return "open (SYN/ACK)"
        if flags & 0x04:                # RST
            return "refused (RST)"
        return f"unexpected TCP flags={flags}"
    if reply.haslayer(ICMP):
        t = reply[ICMP].type
        c = reply[ICMP].code
        return f"rejected (ICMP type={t} code={c})"
    return "unknown reply"


results = Counter()
for i in range(count):
    r = sr1(IP(dst=target)/TCP(dport=port, flags="S"),
            timeout=timeout, verbose=0)
    results[classify(r)] += 1

parts = [f"{n}/{count} {label}" for label, n in results.most_common()]
print(f"{target}:{port} -> " + ", ".join(parts))

# Hint at the verdict when one outcome dominates
top_label, top_n = results.most_common(1)[0]
if top_n == count:
    if top_label == "silently dropped":
        print("  verdict: NetworkPolicy or CNI blackhole")
    elif top_label == "open (SYN/ACK)":
        print("  verdict: path open, listener present")
    elif top_label == "refused (RST)":
        print("  verdict: path open, no listener on that port")
    elif top_label.startswith("rejected"):
        print("  verdict: explicit firewall reject in path")
