# Routes and interfaces

`ip route` is faster to type. Use Scapy when you want to **interrogate**
the routing table from the same place you're crafting the packet, or when
you're inside a stripped-down container with no `iproute2`.

Everything below assumes you're at the ttyd prompt at
**http://localhost:8080**.

## What does this host think the network looks like?

Drop into `scapy` and ask:

```python
conf.route        # IPv4 routing table
conf.route6       # IPv6
conf.ifaces       # all interfaces Scapy can see
```

`conf.route` prints something like:

```
Network          Netmask          Gateway     Iface  Output IP   Metric
0.0.0.0          0.0.0.0          10.0.0.1    eth0   10.0.0.5    0
10.0.0.0         255.255.0.0      0.0.0.0     eth0   10.0.0.5    0
127.0.0.0        255.0.0.0        0.0.0.0     lo     127.0.0.1   0
```

## Which interface will a packet leave on?

```python
conf.route.route("8.8.8.8")
# -> ('eth0', '10.0.0.5', '10.0.0.1')   (iface, source IP, next hop)
```

This is the single most useful function on this page. If a Scapy script
"works on localhost but not against the real server", 80% of the time
`conf.route.route(target)` is picking an interface you didn't expect.

## "Where is this IP, really?"

Combined check — Scapy's route + ARP for the next hop + a real ICMP
probe:

```sh
python3 /app/scripts/routes/whereis.py 8.8.8.8
python3 /app/scripts/routes/whereis.py 10.0.0.1
```

Output:

```
8.8.8.8: via eth0 src 10.0.0.5 gw 10.0.0.1
  next-hop MAC: aa:bb:cc:dd:ee:ff
  ping: OK (8.8.8.8)
```

If route looks right but MAC is empty, ARP is failing for the gateway.
If MAC is fine but ping fails, the host or a downstream firewall is
dropping you.

## Picking the interface explicitly

```python
conf.iface = "eth1"                                    # for everything after
sniff(iface="eth1", count=10)                          # one-shot override
sr1(IP(dst="10.1.2.3")/ICMP(), iface="eth1", verbose=0)
```

In single-interface containers this rarely matters. In multi-homed nodes,
VPN gateways, or nodes with a sidecar CNI, it matters a lot.

## Adding a route inside the container

```python
conf.route.add(net="172.30.0.0/16", gw="10.0.0.254")
conf.route.delt(net="172.30.0.0/16", gw="10.0.0.254")
```

These are Scapy-internal — they tell Scapy where to send packets, but they
**do not** touch the kernel routing table. If you want the kernel to
route differently, drop to the shell and run `ip route add` (needs
`NET_ADMIN`).

## ARP table

```python
getmacbyip("10.0.0.1")          # ARPs if not cached, returns MAC
conf.netcache.arp_cache         # current cache
```

## Multiple routing tables

Linux policy routing (`ip rule`) is invisible to Scapy — `conf.route`
only reflects table `main`. If a packet leaves on a surprising interface
and the rest of this page doesn't explain it, drop to a shell and run:

```sh
ip rule
ip route show table all
```

Then come back to Scapy knowing which interface to pin with `iface=`.
