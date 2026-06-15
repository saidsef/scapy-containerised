#!/usr/bin/env python3
"""Stream packets straight to disk so a long capture won't OOM.
sync=True flushes each packet — the file stays usable even if the
container is killed.

Copy out with:
  docker cp <ctr>:/tmp/cap.pcap .
  kubectl -n <ns> cp <pod>:/tmp/cap.pcap ./cap.pcap

Usage:  python3 /app/scripts/sniffing/to_pcap.py eth0 'port 443' /tmp/cap.pcap
"""
import sys
from scapy.all import sniff, PcapWriter

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
bpf = sys.argv[2] if len(sys.argv) > 2 else None
out = sys.argv[3] if len(sys.argv) > 3 else "/tmp/cap.pcap"

writer = PcapWriter(out, append=True, sync=True)
print(f"writing to {out} — Ctrl-C to stop")
sniff(iface=iface, filter=bpf, prn=writer.write, store=False, count=0)
