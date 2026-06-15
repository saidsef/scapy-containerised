#!/usr/bin/env python3
"""Issue N DNS queries against a resolver and print a latency histogram.

Helps answer "is DNS the slow thing" by showing min/p50/p90/p99/max
and the timeout count over a sample of serial queries.

Usage:  python3 /app/scripts/dns/latency_histogram.py
        python3 /app/scripts/dns/latency_histogram.py example.com
        python3 /app/scripts/dns/latency_histogram.py example.com 10.96.0.10
        python3 /app/scripts/dns/latency_histogram.py example.com 10.96.0.10 500
"""
import sys
import time
from scapy.all import sr1, IP, UDP, DNS, DNSQR

name = sys.argv[1] if len(sys.argv) > 1 else "kubernetes.default.svc.cluster.local"
resolver = sys.argv[2] if len(sys.argv) > 2 else "10.96.0.10"
count = int(sys.argv[3]) if len(sys.argv) > 3 else 100

samples = []
timeouts = 0

for _ in range(count):
    q = IP(dst=resolver)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name))
    t0 = time.perf_counter()
    r = sr1(q, timeout=2, verbose=0)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    if r is None:
        timeouts += 1
    else:
        samples.append(elapsed_ms)


def pct(sorted_xs, p):
    if not sorted_xs:
        return float("nan")
    k = int(round((len(sorted_xs) - 1) * p))
    return sorted_xs[k]


samples.sort()

print(f"  DNS latency for {name} via {resolver} (n={count})")
if samples:
    print(f"       min: {samples[0]:.1f} ms")
    print(f"       p50: {pct(samples, 0.50):.1f} ms")
    print(f"       p90: {pct(samples, 0.90):.1f} ms")
    print(f"       p99: {pct(samples, 0.99):.1f} ms")
    print(f"       max: {samples[-1]:.1f} ms")
else:
    print("       no successful replies")
print(f"  timed out: {timeouts}/{count}")
