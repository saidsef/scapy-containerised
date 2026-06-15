#!/usr/bin/env python3
"""Ask OpenDNS what source IP it sees you from. That's the IP your
egress NAT / cloud-NAT-gateway is presenting to the public internet.
Compare with a SaaS provider's allowlist when "we're allowlisted but
they still see the wrong IP".

Usage:  python3 /app/scripts/k8s/egress_ip.py
"""
from scapy.all import sr1, IP, UDP, DNS, DNSQR

r = sr1(IP(dst="resolver1.opendns.com")/UDP(dport=53)/
        DNS(rd=1, qd=DNSQR(qname="myip.opendns.com", qtype="A")),
        timeout=3, verbose=0)
if r and r.haslayer(DNS) and r[DNS].ancount:
    print("Egress IP:", r[DNS].an.rdata)
else:
    print("no reply — egress DNS might be intercepted or blocked")
