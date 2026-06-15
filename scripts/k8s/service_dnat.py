#!/usr/bin/env python3
"""Show DNAT happening for a Service ClusterIP. You should see traffic
to the ClusterIP go out and a reply come back from an actual pod IP.
If both directions only ever show the ClusterIP, kube-proxy is broken.

Usage:  python3 /app/scripts/k8s/service_dnat.py 10.96.123.45 443
"""
import sys
from scapy.all import sniff, IP, TCP

clusterip = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 30

bpf = f"tcp port {port} and host {clusterip}"
print(f"sniffing '{bpf}' for {timeout}s ...")
sniff(iface="any", filter=bpf,
      prn=lambda p: print(p[IP].src, "->", p[IP].dst, "flags=", p[TCP].flags),
      store=False, timeout=timeout)
