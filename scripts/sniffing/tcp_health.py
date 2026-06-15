#!/usr/bin/env python3
"""Per-flow TCP health: handshake RTT, retransmits, OOO, zero-window.
The signal for "API slow but dashboard green". Sorted worst-first on retx.

Usage:  python3 /app/scripts/sniffing/tcp_health.py eth0
        python3 /app/scripts/sniffing/tcp_health.py eth0 'host 10.0.0.5' 60
"""
import sys
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
bpf = sys.argv[2] if len(sys.argv) > 2 else "tcp"
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 30

flows = defaultdict(lambda: {"pkts": 0, "bytes": 0, "retx": 0,
                             "ooo": 0, "zwin": 0, "rtt_ms": None})
syns = {}
seen = defaultdict(int)
max_seq = {}


def flow_key(src, sport, dst, dport):
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


def record(p):
    if IP not in p or TCP not in p:
        return
    ip, tcp = p[IP], p[TCP]
    src, dst, sport, dport = ip.src, ip.dst, tcp.sport, tcp.dport
    flags = tcp.flags
    payload_len = len(p[Raw].load) if Raw in p else 0
    key = flow_key(src, sport, dst, dport)
    f = flows[key]
    f["pkts"] += 1
    f["bytes"] += payload_len

    fmask = int(flags) & 0x17
    if fmask == 0x02:
        syns[(src, sport, dst, dport)] = (float(p.time), int(tcp.seq))
    elif fmask == 0x12:
        stash = syns.pop((dst, dport, src, sport), None)
        if stash and tcp.ack == stash[1] + 1:
            f["rtt_ms"] = (float(p.time) - stash[0]) * 1000.0

    if tcp.window == 0 and not (int(flags) & 0x02):
        f["zwin"] += 1

    is_pure_ack = payload_len == 0 and not (int(flags) & 0x07)
    if not is_pure_ack:
        dkey = (src, sport, dst, dport, int(tcp.seq), payload_len)
        seen[dkey] += 1
        if seen[dkey] > 1:
            f["retx"] += 1
        else:
            mkey = (src, sport, dst, dport)
            prev = max_seq.get(mkey)
            if prev is not None and tcp.seq < prev:
                f["ooo"] += 1
            if prev is None or tcp.seq > prev:
                max_seq[mkey] = tcp.seq


print(f"capturing {bpf!r} on {iface} for {timeout}s — Ctrl-C to stop early")
try:
    sniff(iface=iface, filter=bpf, timeout=timeout, prn=record, store=False)
except KeyboardInterrupt:
    pass

rows = sorted(flows.items(), key=lambda kv: kv[1]["retx"], reverse=True)
header = f"{'flow':>44} {'pkts':>6} {'retx':>5} {'ooo':>4} {'zwin':>5} {'rtt_ms':>8}"
print(header)
for (a, b), f in rows:
    label = f"{a[0]}:{a[1]} -> {b[0]}:{b[1]}"
    rtt = f"{f['rtt_ms']:.1f}" if f["rtt_ms"] is not None else "-"
    print(f"{label:>44} {f['pkts']:>6} {f['retx']:>5} {f['ooo']:>4} "
          f"{f['zwin']:>5} {rtt:>8}")
print(f"\n{len(flows)} flows tracked over {timeout}s on {iface}")
