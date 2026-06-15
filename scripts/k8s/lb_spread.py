#!/usr/bin/env python3
"""Fire a batch of SYNs at a Service ClusterIP and report how many
distinct backend pods answer. If you only see one and the Service
has multiple endpoints, suspect session affinity or ipvs sh.

Usage:  python3 /app/scripts/k8s/lb_spread.py 10.96.123.45 80
        python3 /app/scripts/k8s/lb_spread.py 10.96.123.45 80 100
"""
import sys
from scapy.all import sr, IP, TCP

clusterip = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
n = int(sys.argv[3]) if len(sys.argv) > 3 else 50

ans, _ = sr(IP(dst=clusterip)/TCP(sport=range(40000, 40000 + n),
                                  dport=port, flags="S"),
            timeout=2, verbose=0)
backends = {r[1][IP].src for r in ans if r[1][TCP].flags == "SA"}
print(f"{len(backends)} backends answered:")
for b in sorted(backends):
    print(f"  {b}")
