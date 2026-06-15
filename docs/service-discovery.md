# Service discovery from the wire

This guide is about mapping out what's actually happening on a pod or
node — who is calling whom, on what ports, with how much traffic. It is
the "discovery" half of "service discovery": not Kubernetes `Service`
objects, but the empirical map of real traffic.

Everything below assumes you're at the Scapy prompt inside the ttyd
terminal — `python -m scapy.__init__` from the shell.

## Why this question comes up

"What services does this pod depend on" is normally answered in dev by
tracing API calls, or in design review by reading an architecture
diagram. Both go stale. In prod, when something is on fire and you have
five minutes, you want the answer from the wire — what is this process
calling *right now*, not what it was meant to call when someone wrote
the README. Scapy gives you exactly that.

A few situations where the wire-side answer is the only useful one:

- A pod is being deprecated and you want to confirm nothing real is
  still calling it.
- A new egress NetworkPolicy is about to land and you need to know which
  external hosts the workload actually reaches.
- The on-call alert says "service A is degraded" and you want to know
  what service A talks to before you start guessing.
- A sidecar started failing and you want the dependency list for the
  blast-radius write-up.

## The mental model

Every TCP flow has a 4-tuple: `(src_ip, src_port, dst_ip, dst_port)`.
For service mapping, two of those four matter and two don't.

The source port is ephemeral — picked at random by the kernel for each
new connection. Aggregating on it gives you one row per connection,
which is too noisy. Drop it.

The destination port is the service identity — `443` is HTTPS, `5432`
is Postgres, `9092` is Kafka. Keep it.

What you care about is the *connection initiator* — the side that sent
the SYN. The same flow seen from a tap will produce SYN, SYN/ACK, then
data both ways; only the SYN tells you who is the client and who is the
server. Filter for SYN-without-ACK and you get a clean "client calls
server on port" event.

Aggregate over `(src_ip, dst_ip, dst_port)` and you have a directed
graph of "this pod calls these services". For destinations behind a
load balancer or shared frontend, the IP alone won't tell you which
upstream the client wanted — TLS SNI does, and you can stitch it in
from the data captured by `tls_sni.py` (see the sniffing guide).

## Building a directed graph in real time

The simplest form, inline at the prompt:

```python
>>> from collections import defaultdict
>>> edges = defaultdict(int)
>>> def edge(p):
...     if IP in p and TCP in p and int(p[TCP].flags) & 0x12 == 0x02:
...         edges[(p[IP].src, p[IP].dst, int(p[TCP].dport))] += 1
>>> sniff(iface="eth0", filter="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
...       timeout=30, prn=edge, store=False)
>>> for (s, d, dp), n in sorted(edges.items(), key=lambda kv: -kv[1]):
...     print(f"{s:<16} -> {d:<16} {dp:>5} {n:>4}")
```

The flags test `int(flags) & 0x12 == 0x02` keeps SYN-only packets and
drops SYN/ACK, so each connection contributes exactly one record at the
point the client opens it. The BPF filter does the same thing in the
kernel, so userspace only sees the relevant frames.

As a script:

```python
>>> !python3 /app/scripts/discovery/conn_graph.py eth0
>>> !python3 /app/scripts/discovery/conn_graph.py eth0 60
>>> !python3 /app/scripts/discovery/conn_graph.py eth0 60 'not net 10.0.0.0/8'
```

Output:

```
  src              dst              dport   count
  10.244.1.5       -> 10.96.0.42         443     12
  10.244.1.5       -> 10.96.10.1          80      4
  10.244.1.5       -> 8.8.8.8             53      2

1 distinct sources observed
3 distinct destinations from 10.244.1.5 over 30s
```

To stitch SNI into the picture, run `tls_sni.py` in one ttyd tab and
`conn_graph.py` in another, then match destination IPs by hand. Any IP
that appears in both outputs gets a hostname annotation — useful for
LBs and shared ingress where the IP alone is ambiguous.

## Top talkers

Sometimes the question isn't "who" but "what's chewing my bandwidth".
That's a different aggregation: by bytes, folded across direction so
request and reply traffic land in the same row.

```python
>>> !python3 /app/scripts/discovery/talkers.py eth0
>>> !python3 /app/scripts/discovery/talkers.py eth0 60 20
```

Output:

```
        bytes      pkts   pair
    2,341,892     1,521   10.244.1.5  <->  10.96.0.42
      451,002       321   10.244.1.5  <->  10.96.10.1
       12,800        96   10.244.1.5  <->  8.8.8.8
```

The pair is normalised — `(a, b)` and `(b, a)` map to the same key —
so the byte count includes both directions. For a connection where the
pod uploads 2 MB and gets 200 kB back, you see 2.2 MB in one row, not
two rows.

If you want a per-port breakdown instead, swap the aggregation key in
the script to `(src, dst, dport)` and the output sorts by which service
is hottest. The "pair" form is the right default when you don't know
yet what's heavy.

## Cross-namespace and cross-cluster patterns

A pod calling an IP inside your cluster CIDR is service traffic. A pod
calling an IP outside your cluster CIDR is egress — an external API, a
managed database, an S3 bucket, a telemetry sink. The distinction
matters because egress is what your NetworkPolicy, your egress
firewall, and your compliance audit all care about.

To draw the line, pull the cluster's pod and service CIDRs:

```python
>>> !kubectl cluster-info dump | grep -E 'cluster-cidr|service-cluster-ip-range'
```

Or, from inside a pod, the conservative rule of thumb covers most
clusters: treat any RFC1918 address inside your known pod/service CIDR
as cluster, and everything else as egress.

```python
>>> import ipaddress
>>> CLUSTER = [ipaddress.ip_network("10.244.0.0/16"),
...            ipaddress.ip_network("10.96.0.0/12")]
>>> def is_egress(ip):
...     a = ipaddress.ip_address(ip)
...     return not any(a in net for net in CLUSTER)
>>> [(s, d, p) for (s, d, p) in edges if is_egress(d)]
```

That list — destinations outside the cluster CIDRs — is your egress
inventory. If you're about to write an egress NetworkPolicy, that is
exactly the set you need to allow.

## Mapping a service mesh from outside

If the cluster runs Istio or Linkerd, every pod's outbound traffic goes
through its sidecar before it leaves the pod's network namespace. Two
useful consequences for discovery:

The sidecar pod sees all the workload's egress, which means you can
capture on a single envoy/linkerd-proxy pod and get the full set of
dependencies for the meshed app — no per-container coordination.

The traffic between the app container and the sidecar is loopback
(`127.0.0.1`) inside the pod's network namespace, so if you tap inside
the pod and aggregate by source you'll see two distinct pictures —
loopback flows from app to sidecar, then real flows from sidecar
outward. Filter `not src host 127.0.0.1 and not dst host 127.0.0.1`
when you only want the egress side.

```python
>>> !python3 /app/scripts/discovery/conn_graph.py eth0 60 'not host 127.0.0.1'
```

For deeper mesh-specific patterns — mTLS handshakes, sidecar bypass,
xDS traffic to the control plane — the service-mesh guide is the
place.

## What this isn't

The output of these scripts is a snapshot, not a service catalog.
Three caveats worth stating out loud:

A long-lived connection that's open the whole window but doesn't send a
SYN inside it won't show up in `conn_graph.py`. That's by design — the
graph is "new connections initiated" — but it means a quiet
keep-alive will be invisible. If you want to include established flows,
capture without the SYN filter and aggregate on `(src, dst, dport)`
across all TCP packets.

Cron-driven calls run once an hour or once a day. A 30-second window
will miss them. If you're doing dependency discovery for a real
migration, capture for at least the longest cron interval you know
about, or capture in shorter windows across a representative day and
union the results.

UDP isn't covered by the SYN-based graph at all. DNS, NTP, and
in-cluster service discovery go over UDP. If those matter for your
question, capture `udp` separately and aggregate the same way on
`(src, dst, dport)`. There's no "initiator" concept for UDP, so the
direction is whichever side sent the first packet.

Capture for longer than you think you need, sample across a
representative timeframe, and treat the output as evidence — not the
final word.
