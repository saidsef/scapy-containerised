#!/usr/bin/env python3
"""Observe DNS search-path expansion on an interface.

Sniffs UDP/53 for a window and groups queries by source port — each
getaddrinfo call uses a fresh UDP source port and emits all its
expanded queries from the same port. Pairs queries with their replies
and labels the rcode so you can see how many lookups one application
name actually became.

Usage:  python3 /app/scripts/dns/ndots_trace.py
        python3 /app/scripts/dns/ndots_trace.py eth0
        python3 /app/scripts/dns/ndots_trace.py eth0 30
"""
import sys
from collections import defaultdict
from scapy.all import sniff, IP, UDP, DNS, DNSQR

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
timeout_seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 30

RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
QTYPES = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT"}

# keyed by (client_ip, src_port) -> list of dicts with query and reply state
groups = defaultdict(list)
# txid index for matching replies back to queries
by_txid = {}


def on_pkt(p):
    if not p.haslayer(DNS) or not p.haslayer(IP) or not p.haslayer(UDP):
        return
    dns = p[DNS]
    if dns.qr == 0 and dns.qdcount > 0:
        key = (p[IP].src, p[UDP].sport)
        qname = p[DNSQR].qname.decode().rstrip(".") if p[DNSQR].qname else ""
        entry = {
            "qname": qname,
            "qtype": int(p[DNSQR].qtype),
            "resolver": p[IP].dst,
            "rcode": None,
        }
        groups[key].append(entry)
        by_txid[(key, dns.id)] = entry
    else:
        key = (p[IP].dst, p[UDP].dport)
        entry = by_txid.get((key, dns.id))
        if entry is not None and entry["rcode"] is None:
            entry["rcode"] = int(dns.rcode)


print(f"sniffing {iface} for {timeout_seconds}s — trigger a lookup now")
sniff(iface=iface, filter="udp port 53", prn=on_pkt, store=False,
      timeout=timeout_seconds)

print()
print("expansion observed:")
if not groups:
    print("  (no DNS queries seen)")
    sys.exit(0)

for (client, sport), entries in sorted(groups.items()):
    resolver = entries[0]["resolver"]
    print(f"  port {sport} (resolver={resolver}):")
    for i, e in enumerate(entries, 1):
        rcode = e["rcode"]
        if rcode is None:
            label = "no-reply"
        else:
            name = RCODES.get(rcode, "UNKNOWN")
            label = f"rcode={rcode} ({name})"
        qtype_name = QTYPES.get(e["qtype"], f"type={e['qtype']}")
        print(f"    {i}.  {e['qname']:<40} {qtype_name:<5} {label}")

    names = [e["qname"] for e in entries]
    distinct_names = list(dict.fromkeys(names))
    n_names = len(distinct_names)
    rcodes = [e["rcode"] for e in entries]

    if n_names == 1:
        if len(entries) == 1:
            print(f"    -> no expansion (single query)")
        else:
            print(f"    -> 1 name, {len(entries)} queries (A+AAAA pair) — no expansion")
    elif all(rc == 3 for rc in rcodes):
        print(f"    -> {n_names} names tried, all NXDOMAIN — likely a typo, plus ndots:5 expansion")
    elif rcodes and rcodes[-1] == 0:
        print(f"    -> {n_names} names tried, final NOERROR — ndots:5 expansion")
    else:
        print(f"    -> {n_names} names, mixed rcodes")
