# Routes and interfaces

This guide is about understanding how your host (or container, or pod)
makes routing decisions, and how to use Scapy to interrogate those
decisions from the same place you're crafting packets. If you've ever
been surprised by a packet leaving on the wrong interface, this is the
place to start.

`ip route` is faster to type when you just want to read the table. The
case for Scapy here is twofold: you can ask "what would happen if I sent
to X" in one call (`conf.route.route("X")`), and you can do it inside the
same Python session where you're building the packet, which means no
context-switching between tools.

Everything below assumes you're at the Scapy prompt — `python -m scapy.__init__`
from the ttyd terminal.

## What does this host think the network looks like?

Scapy reads the routing table at import and exposes it through `conf`:

```python
>>> conf.route        # IPv4 routing table
>>> conf.route6       # IPv6
>>> conf.ifaces       # all interfaces Scapy can see
```

`conf.route` prints something like:

```
Network          Netmask          Gateway     Iface  Output IP   Metric
0.0.0.0          0.0.0.0          10.0.0.1    eth0   10.0.0.5    0
10.0.0.0         255.255.0.0      0.0.0.0     eth0   10.0.0.5    0
127.0.0.0        255.0.0.0        0.0.0.0     lo     127.0.0.1   0
```

`conf.ifaces` is more useful than `ip link` for some queries because each
interface is a Python object — you can poke at it programmatically:

```python
>>> conf.ifaces["eth0"].mac
'aa:bb:cc:dd:ee:ff'
>>> conf.ifaces["eth0"].ip
'10.0.0.5'
```

## Which interface will a packet leave on?

This is the single most useful function on this page:

```python
>>> conf.route.route("8.8.8.8")
('eth0', '10.0.0.5', '10.0.0.1')
```

The return tuple is `(iface, source_ip, gateway)`. If a Scapy script
"works against localhost but not the real server", the answer is almost
always that `conf.route.route(target)` is picking an interface or source
address you didn't expect. Run that one call first when something looks
strange.

## A combined "where is this IP, really?" check

Three questions you'll ask about an IP — "what does my routing table say",
"is ARP working for the next hop", and "does the host actually answer" —
can be answered in one pass:

```python
>>> def whereis(ip):
...     iface, src, gw = conf.route.route(ip)
...     print(f"{ip}: via {iface} src {src} gw {gw}")
...     mac = getmacbyip(gw) if gw != "0.0.0.0" else "(direct, no gw)"
...     print(f"  next-hop MAC: {mac}")
...     r = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
...     print(f"  ping: {'OK' if r else 'no reply'}")
>>> whereis("8.8.8.8")
>>> whereis("10.0.0.1")
```

If the route looks right but the MAC is empty, ARP is failing for the
gateway — that's an L2 problem. If the MAC is fine but the ping fails,
the path is up to the gateway and the rest is somewhere downstream.

As a script:

```python
>>> !python3 /app/scripts/routes/whereis.py 8.8.8.8
>>> !python3 /app/scripts/routes/whereis.py 10.0.0.1
```

## Forcing the interface

Most of the time Scapy's automatic routing is fine. When you're on a
multi-homed host, a node running a VPN, or a node with a sidecar CNI,
you may need to pin a specific interface. Two ways:

Persistently, for everything that follows:

```python
>>> conf.iface = "eth1"
```

Just for one call:

```python
>>> sniff(iface="eth1", count=10)
>>> sr1(IP(dst="10.1.2.3")/ICMP(), iface="eth1", verbose=0)
```

In a single-interface container this rarely matters. In multi-homed nodes
it matters a lot, and `conf.route.route(target)` is your fastest debug.

## Inspecting and adjusting ARP

```python
>>> getmacbyip("10.0.0.1")
'aa:bb:cc:dd:ee:01'
>>> conf.netcache.arp_cache
```

`getmacbyip` issues an ARP request if the entry isn't cached, then
returns the MAC. `conf.netcache.arp_cache` is the current cache as a
dict.

## Adjusting routes from Scapy

```python
>>> conf.route.add(net="172.30.0.0/16", gw="10.0.0.254")
>>> conf.route.delt(net="172.30.0.0/16", gw="10.0.0.254")
```

These changes are Scapy-internal — they tell Scapy where to send the
packets *it* generates. They do not touch the kernel's routing table.
If you want the kernel to route differently, drop to the shell and run
`ip route add` (you'll need `NET_ADMIN`).

This distinction matters more than it looks. If you're testing a
workaround that depends on the kernel rewriting traffic, changing
`conf.route` won't help. If you're testing a Scapy-generated probe and
want it to go a specific way without touching the kernel, this is
exactly the right tool.

## When the route is in a different table

Linux policy routing (`ip rule`) is invisible to `conf.route` — Scapy
only reflects the `main` table. If a packet keeps leaving on an
interface you can't explain and `conf.route.route` agrees with you that
it shouldn't, there's a `ip rule` directing it elsewhere. Drop to a
shell:

```python
>>> !ip rule
>>> !ip route show table all
```

Then come back to Scapy knowing which interface you actually need to
pin.
