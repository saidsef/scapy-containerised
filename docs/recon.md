# Reconnaissance

This guide covers using Scapy to map out a network — who is on it, what
ports they have open, how the path to a remote host looks, and how to
make educated guesses about what's running where.

A note before anything else: the techniques in this guide observe and
probe networks, and many of them generate traffic that will show up in
intrusion-detection systems. Run them on networks you own or have written
permission to test. If you're inside this container running against a
production system you don't own, stop.

Every example below assumes you're at the Scapy prompt — start it from
the ttyd terminal with `python -m scapy.__init__`.

## Finding hosts on your local L2

The lowest-cost way to enumerate hosts on the same broadcast domain as
you is an ARP sweep. ARP doesn't get logged in most environments, doesn't
cross routers, and is very fast — a /24 typically completes in a second
or two.

```python
>>> arping("10.0.0.0/24")
```

You'll get a printed table and Scapy returns `(answered, unanswered)` as
a tuple, so you can keep the results if you want to do something with
them:

```python
>>> ans, _ = arping("10.0.0.0/24", verbose=0)
>>> [(r[1].psrc, r[1].src) for r in ans]
[('10.0.0.1', 'aa:bb:cc:dd:ee:01'), ('10.0.0.5', 'aa:bb:cc:dd:ee:05'), ...]
```

If the only MAC you see in the response is your own, you're probably on
a switched VLAN with port security, or inside a container where the
bridge network only puts you next to the gateway. The
[Kubernetes guide](kubernetes.md) goes into what to do in that case.

The same workflow is wrapped as a script for one-shot use:

```python
>>> !python3 /app/scripts/recon/arp_sweep.py 10.0.0.0/24
```

## Reaching across an L3 boundary

ARP doesn't cross routers, so for anything outside your immediate subnet
you need ICMP. Most operating systems still respond to echo requests by
default, though plenty of cloud workloads have it disabled.

```python
>>> ans, _ = sr(IP(dst="10.0.0.0/24")/ICMP(), timeout=2, verbose=0)
>>> ans.summary(lambda r: r[1].sprintf("%IP.src% is up"))
```

If the sweep comes back empty against hosts you know exist, it usually
means ICMP is being dropped — try the SYN scan below against port 443 or
22 instead. Almost nothing drops those without responding.

As a script:

```python
>>> !python3 /app/scripts/recon/icmp_sweep.py 10.0.0.0/24
```

## Looking at ports on a single host

A TCP SYN scan is the fastest way to ask "what is this host listening
on?" Scapy is not nmap — for thousands of ports you want the real thing —
but for a short list it's perfectly fine and you get full control over
how the packets look.

```python
>>> ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9090]
>>> ans, _ = sr(IP(dst="10.0.0.5")/TCP(dport=ports, flags="S"),
...             timeout=2, verbose=0)
>>> for snd, rcv in ans:
...     if rcv[TCP].flags == "SA":
...         print(rcv.sport, "open")
...     elif rcv[TCP].flags == "RA":
...         print(rcv.sport, "closed")
```

A `SA` (SYN/ACK) means the port is open and a listener answered. `RA`
(RST/ACK) means the port is reachable but nobody's home. Silence usually
means a firewall is filtering, or the host itself is unreachable.

It's polite to send a RST to close the half-open connections you just
opened so the target's TCP stack stops waiting on them:

```python
>>> for snd, rcv in ans:
...     if rcv[TCP].flags == "SA":
...         send(IP(dst=rcv.src)/TCP(sport=snd.sport, dport=rcv.sport,
...                                  flags="R", seq=rcv.ack), verbose=0)
```

The script version does both the scan and the cleanup:

```python
>>> !python3 /app/scripts/recon/syn_scan.py 10.0.0.5 22,80,443,8080
```

## Tracing the path to a host

A text traceroute is one line:

```python
>>> res, _ = traceroute(["saidsef.co.uk"], maxttl=20, verbose=0)
>>> res.show()
```

If you've mounted the GeoIP2 city database into the container
(`-v $PWD/geoip:/data` on `docker run`), you can render the path on a
world map:

```python
>>> conf.geoip_city = "/data/GeoLite.mmdb"
>>> conf.temp_files = "/tmp"
>>> res = traceroute_map(["saidsef.co.uk", "google.com"], verbose=0)
>>> res.world_trace()
```

`world_trace` calls into PyX, which calls into a real LaTeX engine to
render the map. The image is built with `texlive` and `ghostscript`
already installed for this reason — if you see "PyX dependencies not
installed", you're on an older build.

The script wraps the GeoIP setup so you don't have to remember the conf
keys:

```python
>>> !python3 /app/scripts/recon/traceroute_world.py saidsef.co.uk
```

Output is `/tmp/world_trace.pdf`. Copy it out from a host shell with
`docker cp` or `kubectl cp`.

## Making a guess at what OS a host is running

Scapy ships with an active nmap-style fingerprint module, but it needs an
external fingerprints file that isn't in this image. For most quick
triage, the cheaper passive approach is good enough: look at the TTL and
TCP window size on the first SYN you see from each new host.

```python
>>> def guess_os(p):
...     if not (p.haslayer(IP) and p.haslayer(TCP)): return
...     ttl, win = p[IP].ttl, p[TCP].window
...     if ttl <= 64  and win in (5840, 14600, 29200, 65535): hint = "linux"
...     elif ttl <= 128 and win in (8192, 64240, 65535):       hint = "windows"
...     elif ttl <= 255:                                       hint = "cisco/bsd"
...     else:                                                  hint = "?"
...     print(f"{p[IP].src:>15}  ttl={ttl:<3} win={win:<6}  -> {hint}")
>>> sniff(iface="eth0",
...       lfilter=lambda p: TCP in p and p[TCP].flags == "S",
...       prn=guess_os, count=50)
```

It is a guess. Containers commonly forward packets that have already been
through a host stack, virtualisation NICs change windows, and load
balancers normalise both. Treat the output as a hint, not an answer.

As a script:

```python
>>> !python3 /app/scripts/recon/passive_os.py eth0 50
```

## Probing DNS

When you want to know whether a name resolves from where you are — not
from your laptop — Scapy can build the query directly. This bypasses
whatever resolver is configured in `/etc/resolv.conf` and tests the path
to a specific server.

```python
>>> for sub in ("www", "api", "auth", "mail", "vpn", "git", "admin"):
...     q = IP(dst="1.1.1.1")/UDP(dport=53)/DNS(rd=1,
...           qd=DNSQR(qname=f"{sub}.example.com"))
...     r = sr1(q, timeout=1, verbose=0)
...     if r and r.haslayer(DNS) and r[DNS].ancount > 0:
...         print(sub, "->", r[DNS].an.rdata)
```

For anything heavier — zone transfers, AXFR attempts, DNSSEC validation —
reach for `dig` or `dnsx`. This pattern is meant for the "I'm already
inside a container that can't escape to the public internet, does
internal DNS resolve X" question.

```python
>>> !python3 /app/scripts/recon/dns_probe.py example.com
```

## Looking at an unknown protocol on the wire

Eventually you'll be asked to debug something running on a port whose
protocol you don't have docs for. The first move is always to look at
the bytes:

```python
>>> pkts = sniff(filter="tcp port 4000", count=50, timeout=30)
>>> for p in pkts:
...     if Raw in p:
...         print(p[IP].src, "->", p[IP].dst)
...         hexdump(p[Raw].load)
```

Once you've seen enough flows to spot the framing — fixed-length headers,
length prefixes, magic bytes — you can define a `Packet` subclass that
dissects it for you. Scapy's
[guide to building a layer](https://scapy.readthedocs.io/en/latest/build_dissect.html)
walks through that in detail.

```python
>>> !python3 /app/scripts/recon/raw_dump.py 4000 50
```
