#!/usr/bin/env python3
"""Print everything the pod (or node, if hostNetwork=true) thinks about
its own network. First thing to run when "the pod can't reach X".

Usage:  python3 /app/scripts/k8s/pod_iface.py
"""
from scapy.all import conf

print("=== Interfaces ===")
print(conf.ifaces)

print("\n=== IPv4 routes ===")
print(conf.route)

print("\n=== IPv6 routes ===")
print(conf.route6)
