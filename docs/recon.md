# Reconnaissance

What lives on this network, what ports are open, what does the path to a
host look like. None of this is subtle — if you run it on someone else's
network without permission you will get caught and you will deserve it.

Everything here assumes you're at the ttyd prompt at
**http://localhost:8080**. Each section is "run this script" or "drop into
`scapy` and paste this".

## Who is on my L2?

ARP sweep of the local subnet. Faster and quieter than ping sweeping.

```sh
python3 /app/scripts/recon/arp_sweep.py 10.0.0.0/24
```

If you only see your own MAC, you're on a switched VLAN with port
security, or you're inside a container with a bridge network — see
[kubernetes.md](kubernetes.md).

Need the live results inside a Python session for follow-up work? Drop
into `scapy`:

```python
ans, _ = arping("10.0.0.0/24", verbose=0)
hosts = [(r[1].psrc, r[1].src) for r in ans]
```

## Ping sweep across an L3 boundary

ARP doesn't cross routers. Use ICMP:

```sh
python3 /app/scripts/recon/icmp_sweep.py 10.0.0.0/24
```

A lot of hosts drop ICMP. If the sweep looks empty, try a TCP SYN sweep
to port 443 or 22 — almost nothing drops those silently. See the next
section.

## Port scan

Quick TCP SYN scan of a host. Scapy is not nmap — for a handful of
ports, this is fine; for thousands, use nmap.

```sh
# defaults to a common-ports list
python3 /app/scripts/recon/syn_scan.py 10.0.0.5

# specify ports
python3 /app/scripts/recon/syn_scan.py 10.0.0.5 22,80,443,8080
```

`SA` in the output = SYN/ACK = listener answered (open). `RA` = RST/ACK =
port reachable but nobody's home (closed). Silence = filtered or host
dead. The script tears down half-open sockets with RST so the target
stops waiting.

## What does the path look like?

Standard text traceroute, straight from `scapy`:

```python
res, _ = traceroute(["saidsef.co.uk"], maxttl=20, verbose=0)
res.show()
```

If you've mounted the GeoIP2 city database (`-v $PWD/geoip:/data` on the
docker run), draw the world map:

```sh
python3 /app/scripts/recon/traceroute_world.py saidsef.co.uk
```

Writes `/tmp/world_trace.pdf`. Copy it out:

```sh
# from your host shell, not from ttyd
docker cp <container>:/tmp/world_trace.pdf .
kubectl -n scapy cp <pod>:/tmp/world_trace.pdf ./world_trace.pdf
```

`world_trace` needs PyX, matplotlib, and the texlive/ghostscript packages
that are baked into this image. If it errors with "PyX dependencies not
installed", you're running an old build — rebuild from this repo.

## OS fingerprinting

Scapy has a built-in nmap-style active fingerprint module, but it needs
extra data files. For most cases, passive `p0f`-style fingerprinting on
inbound SYNs is more useful:

```sh
python3 /app/scripts/recon/passive_os.py eth0 50
```

Reads 50 inbound TCP SYNs, guesses the OS from TTL and TCP window size.
It is a guess. Treat it as one.

## DNS reconnaissance

Quick zone-walk style probe against a resolver:

```sh
python3 /app/scripts/recon/dns_probe.py example.com
python3 /app/scripts/recon/dns_probe.py example.com 8.8.8.8
```

For anything serious, use `dnsx` or `dig +trace`. This is the "I'm
already inside the container, I just want to know if internal DNS
resolves X" version.

## Reverse-engineering an unknown protocol

Binary protocol on a port, no spec. Capture a few flows and hexdump:

```sh
python3 /app/scripts/recon/raw_dump.py 4000 50
```

Once you see the framing, define a `Packet` subclass with the field
layout. The Scapy
[build-your-own-layer guide](https://scapy.readthedocs.io/en/latest/build_dissect.html)
is the right next step.
