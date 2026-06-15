#!/usr/bin/env python3
"""Walk a pcap (any size — uses streaming reader) and print every DNS
question.

Usage:  python3 /app/scripts/sniffing/pcap_dns.py /tmp/cap.pcap
"""
import sys
from scapy.all import PcapReader, DNS, DNSQR

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cap.pcap"

with PcapReader(path) as pr:
    for p in pr:
        if p.haslayer(DNS) and p[DNS].qr == 0 and p.haslayer(DNSQR):
            print(p[DNSQR].qname.decode().rstrip("."))
