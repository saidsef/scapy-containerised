#!/usr/bin/env python3
"""Sniff N packets and write a packet-size histogram to a PNG.

Usage:  python3 /app/scripts/sniffing/plot_sizes.py eth0 2000 /tmp/sizes.png
"""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import sniff

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
out = sys.argv[3] if len(sys.argv) > 3 else "/tmp/sizes.png"

print(f"capturing {count} packets on {iface} ...")
pkts = sniff(iface=iface, count=count, timeout=60)
pkts.plot(lambda p: len(p))
plt.gcf().savefig(out)
print(f"wrote {out}")
