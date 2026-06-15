#!/usr/bin/env python3
"""Hand-roll a DNS query straight at kube-dns. Bypasses the libc
resolver and the pod's /etc/resolv.conf — tells you whether
*the network path* to CoreDNS is fine.

Find the resolver:
  kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'

Usage:  python3 /app/scripts/k8s/dns_check.py
        python3 /app/scripts/k8s/dns_check.py 10.96.0.10 myapp.default.svc.cluster.local
"""
import sys
from scapy.all import sr1, IP, UDP, DNS, DNSQR

resolver = sys.argv[1] if len(sys.argv) > 1 else "10.96.0.10"
names = sys.argv[2:] or [
    "kubernetes.default.svc.cluster.local",
    "kube-dns.kube-system.svc.cluster.local",
    "example.com",
]

for name in names:
    q = IP(dst=resolver)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name))
    r = sr1(q, timeout=2, verbose=0)
    if not r or not r.haslayer(DNS):
        print(f"{name:<55} no reply from {resolver}")
        continue
    print(f"{name:<55} rcode={r[DNS].rcode} answers={r[DNS].ancount}")
    if r[DNS].ancount:
        print(f"  -> {r[DNS].an.summary()}")
