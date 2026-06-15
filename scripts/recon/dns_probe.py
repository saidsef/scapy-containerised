#!/usr/bin/env python3
"""Probe a domain for common subdomains via a single resolver.

Usage:  python3 /app/scripts/recon/dns_probe.py example.com
        python3 /app/scripts/recon/dns_probe.py example.com 8.8.8.8
"""
import sys
from scapy.all import sr1, IP, UDP, DNS, DNSQR

domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
resolver = sys.argv[2] if len(sys.argv) > 2 else "1.1.1.1"
subs = ["www", "api", "auth", "mail", "vpn", "git", "admin", "stage", "dev",
        "internal", "k8s", "grafana", "prometheus"]

for sub in subs:
    name = f"{sub}.{domain}"
    q = IP(dst=resolver)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name))
    r = sr1(q, timeout=1, verbose=0)
    if r and r.haslayer(DNS) and r[DNS].ancount > 0:
        print(f"{name:<40} -> {r[DNS].an.rdata}")
