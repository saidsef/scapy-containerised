# CNI overlays

This guide is about inspecting CNI overlay traffic — the encapsulated
tunnel packets that carry pod-to-pod traffic between nodes when the CNI
uses an overlay rather than routing pod CIDRs natively. It is written
for the operator who suspects "the underlay is fine but the overlay is
broken" and needs to look at both layers at the same time.

`tcpdump` will show you the outer packets. Scapy earns its keep here
because it can dissect the outer transport, peel the encapsulation, and
hand you back a normal `IP/TCP` packet you can filter and reason about
in one session.

Every example assumes you're at the Scapy prompt inside the ttyd
terminal — `python -m scapy.__init__` from the shell. The Scapy pod
needs `hostNetwork: true` for the outer NIC to show real underlay
traffic; without it you only see what's already been decapsulated by the
kernel onto the pod's veth.

## 1. Why overlays exist

CNIs fall into two camps. Native-routing CNIs (Calico in BGP mode, AWS
VPC CNI, GKE alias-IP) advertise pod CIDRs into the underlying network
and let the existing routers forward pod packets directly. There is no
encapsulation: a packet from pod A to pod B is the same bytes on the
wire as on the pod's veth, just routed.

Overlay CNIs (Flannel VXLAN, Calico in VXLAN or IPIP mode, Cilium in
VXLAN or Geneve mode, Antrea, Weave) wrap the pod packet inside a
tunnel between the two nodes. The underlay only ever sees node-to-node
traffic on a single transport port; it does not need to know pod CIDRs
exist. That isolation is the whole point — you can run a pod network on
top of any L3 fabric.

The cost is two-fold. Every packet pays an encapsulation header (typical
50–80 bytes), so the pod MTU is smaller than the underlay MTU. And
debugging gains one layer: a broken flow can be broken at the inner
level (pod sent wrong thing), the encapsulation level (tunnel dropped or
mis-routed), or the underlay (node-to-node path broken). You need to be
able to look at all three.

## 2. The common encapsulations

The four you will meet in practice:

- **VXLAN** — UDP, default port **4789**. The payload is an 8-byte
  VXLAN header carrying a 24-bit VNI (the tenant/segment identifier),
  then a full inner Ethernet frame. Used by Flannel (default), Calico
  (`vxlanMode: Always`), Cilium (default), Antrea.
- **Geneve** — UDP, default port **6081**. A variable-length header
  with TLV options, then inner Ethernet. The on-wire shape is similar
  to VXLAN; the options field is what makes it interesting for
  Cilium's per-packet metadata. Geneve is the modern choice for
  Cilium and Open vSwitch.
- **IPIP** — IP protocol **4** (not UDP). The outer IP header is
  followed directly by another IP header. No L2 in the tunnel, no
  port number. Used by Calico in `ipipMode: Always` and by some
  legacy Flannel setups.
- **WireGuard** — UDP, typically port **51820**. The payload is
  encrypted, so you can see endpoints, port, and packet size, but
  nothing inside. Used by Calico WireGuard, Cilium WireGuard, and
  Tailscale-style sidecars.

If you don't know which one is in play, look at the pod's default route
and walk one hop:

```python
>>> conf.route.route("10.244.5.10")   # some remote pod IP
('eth0', '10.244.1.4', '10.244.1.1')
>>> !ip -d link show
```

The `ip -d link show` output names the tunnel interface and its kind
(`vxlan`, `geneve`, `ipip`, `wireguard`).

## 3. Where to sniff

A hostNetwork Scapy pod sees the host's interfaces. There are two that
matter:

- The **underlay NIC** (commonly `eth0`, `ens5`, `bond0`) carries
  *outer* packets — VXLAN/Geneve UDP, IPIP, WireGuard UDP — between
  nodes. This is where you go to ask "is encapsulation working".
- The **tunnel interface** (`flannel.1`, `vxlan.calico`,
  `cilium_vxlan`, `cilium_geneve`, `tunl0` for IPIP) carries
  *inner* packets — the already-decapsulated pod traffic. This is the
  same view a pod gets on its own eth0 for cross-node traffic.

Two examples on the same node:

```python
>>> sniff(iface="eth0", filter="udp port 4789", count=5).summary()
>>> sniff(iface="flannel.1", count=5).summary()
```

The first shows VXLAN-wrapped node-to-node traffic. The second shows the
pod packets that were inside it.

A rule of thumb: when an operator says "pod A can't reach pod B", start
on the *sending* node's tunnel interface to confirm the inner packet is
being produced at all. If it is, move to the same node's underlay NIC to
confirm encapsulation. Then repeat on the receiving node, in reverse.

## 4. MTU and the overlay

Every encapsulation eats bytes:

- VXLAN over IPv4: 50 bytes (14 inner Ethernet + 8 VXLAN + 8 UDP + 20
  outer IP).
- VXLAN over IPv6: 70 bytes.
- Geneve: 50 bytes minimum, more if options are present.
- IPIP: 20 bytes.
- WireGuard: 60 bytes (typical).

If the underlay MTU is 1500 and the CNI uses VXLAN, the pod MTU needs to
be 1450 or lower. Stack two encapsulations — WireGuard over VXLAN,
common on Cilium with transparent encryption — and you owe both
headers, so 1390 is the safe pod MTU.

The classic symptom is "small things work, large things hang": TCP
handshakes and small HTTP requests pass, but a large POST or a TLS
ClientHello-plus-cert stalls forever. PMTU discovery is supposed to fix
this, but ICMP "fragmentation needed" messages are routinely dropped by
cloud underlays. The `pmtu` script confirms the working size from the
sender's perspective:

```python
>>> !python3 /app/scripts/k8s/pmtu.py 10.244.5.10
```

If 1500 fails, 1450 works, and the CNI is VXLAN, you've found the
overhead. If 1450 also fails, you have a second encapsulation in the
path.

## 5. Decoding VXLAN inner traffic

Scapy has VXLAN built in (`scapy.layers.vxlan`), so it's available at
the prompt without `load_contrib`. A VXLAN packet has the shape
`Ether/IP/UDP/VXLAN/Ether/IP/...`. The second `IP` is the inner packet:

```python
>>> pkts = sniff(iface="eth0", filter="udp port 4789", count=20)
>>> p = pkts[0]
>>> p[VXLAN].vni
4096
>>> p.getlayer(IP, 2).src, p.getlayer(IP, 2).dst
('10.244.1.5', '10.244.2.7')
```

`getlayer(IP, 2)` asks for the second IP layer — the inner one. From
there you can drill down as normal:

```python
>>> inner = p.getlayer(IP, 2)
>>> if TCP in inner:
...     print(inner[TCP].sport, "->", inner[TCP].dport, inner[TCP].flags)
```

The packaged script does this in one go and prints one line per packet:

```python
>>> !python3 /app/scripts/cni/vxlan_decode.py eth0
>>> !python3 /app/scripts/cni/vxlan_decode.py eth0 200 4789
```

Output:

```
underlay 10.0.0.1 -> 10.0.0.2  vni=4096  inner 10.244.1.5 -> 10.244.2.7  TCP 51234 -> 443  [SA]
```

## 6. Decoding Geneve

Geneve lives in `scapy.contrib.geneve` and needs an explicit load:

```python
>>> load_contrib("geneve")
>>> from scapy.contrib.geneve import GENEVE
>>> pkts = sniff(iface="eth0", filter="udp port 6081", count=20)
>>> p = pkts[0]
>>> p[GENEVE].vni
4242
>>> p.getlayer(IP, 2).src
'10.244.3.11'
```

The shape is `Ether/IP/UDP/GENEVE/Ether/IP/...`, same pattern as VXLAN.
The packaged script:

```python
>>> !python3 /app/scripts/cni/geneve_decode.py eth0
>>> !python3 /app/scripts/cni/geneve_decode.py eth0 200 6081
```

Cilium's Geneve options (security identity, source identity) are in the
`options` field if you need them; for most debugging the VNI and inner
5-tuple are enough.

## 7. IPIP

IPIP has no UDP — it sits directly on IP protocol 4. Scapy's `IP`
dissector recognises protocol 4 and decodes the inner IP automatically,
so `pkt[IP][IP]` gives you the inner packet with no helper:

```python
>>> pkts = sniff(iface="eth0", filter="ip proto 4", count=10)
>>> p = pkts[0]
>>> p[IP].src, p[IP].dst                # outer = nodes
('10.0.0.1', '10.0.0.2')
>>> p[IP][IP].src, p[IP][IP].dst        # inner = pods
('10.244.1.5', '10.244.2.7')
```

There's no VNI in IPIP, which means no multi-tenancy at the encap
level — the segregation is purely whatever the pod CIDR allocation
implies. If you're debugging Calico in IPIP mode, the inner IP is all
you get.

## 8. WireGuard

The payload is encrypted, so there's no inner dissection to do. The
metadata is still informative:

```python
>>> sniff(iface="eth0", filter="udp port 51820",
...       prn=lambda p: print(p[IP].src, "->", p[IP].dst,
...                           "len", len(p), "type",
...                           p[Raw].load[0] if Raw in p else "-"),
...       count=20)
```

The first byte of the WireGuard payload identifies the message type: 1
is handshake initiation, 2 is handshake response, 3 is cookie reply, 4
is transport data. A healthy peer pair shows a 1 / 2 handshake exchange
followed by a stream of type-4 frames.

Two things to look for at this level. First, persistent-keepalive
traffic: by default WireGuard sends a 32-byte keepalive every 25
seconds in each direction when the link is otherwise idle. If you don't
see those, the peer is either misconfigured or down. Second, packet
sizes — encryption adds 32 bytes of overhead per packet, so a 1450-byte
pod packet becomes a 1482-byte WireGuard packet. Stacked over VXLAN
this is where the MTU math gets painful.

## 9. Asymmetric routing across the overlay

When pod A on node 1 talks to pod B on node 2, the underlay carries the
encapsulated packets between node 1 and node 2. In overlay mode this is
usually symmetric — both directions take the same tunnel. In native BGP
setups it is *not* guaranteed: the underlay routers may choose a
different return path, especially with ECMP across multiple links.

The classic asymmetric-routing failure: pod A sends SYN, node 2 sees it
arrive and pod B replies with SYN/ACK, but the SYN/ACK takes a return
path that gets filtered (stateful firewall, security group, IPS) because
the firewall on the return path never saw the SYN. From pod A's view
the connection times out.

To confirm, capture on both nodes' underlay NICs at the same time. From
a Scapy pod on each node:

```python
>>> sniff(iface="eth0",
...       filter="udp port 4789 and host <other-node-ip>",
...       count=50).summary()
```

On the sending node you should see encapsulated SYN going out and the
SYN/ACK coming back. On the receiving node you should see the SYN
arriving and the SYN/ACK leaving. If the receiving node logs the
outgoing SYN/ACK but the sending node never sees it arrive, the return
path is broken in the underlay — not in the CNI.

The same pattern applies to native-routing CNIs, except you skip the
encapsulation filter and look at the bare pod IPs on the underlay NIC.
If Calico is in BGP mode and the route to pod B is via one ToR but the
return is via another, the inner traffic is right there in the clear.
