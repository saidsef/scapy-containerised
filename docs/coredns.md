# CoreDNS and DNS in Kubernetes

This guide is about DNS specifically as it behaves inside a Kubernetes
cluster — the path a query takes, why a pod can issue five UDP packets
to look up one hostname, and how to tell from the wire whether your
slowness is DNS or something else. `docs/kubernetes.md` shows a single
hand-rolled query straight at kube-dns to prove the path is up; this
guide is what you reach for when the path is up but the application
still feels wrong.

Every example below assumes you're at the Scapy prompt inside the ttyd
terminal — `python -m scapy.__init__` from the shell.

## 1. The path a DNS query takes from a pod

A pod's `/etc/resolv.conf` looks roughly like this:

```
nameserver 10.96.0.10
search default.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
```

`10.96.0.10` is the ClusterIP of the `kube-dns` Service in
`kube-system`. It is not an address that anything listens on directly —
it's a virtual IP, intercepted by `kube-proxy` (iptables or IPVS) or by
the cluster's eBPF dataplane, and translated to one of the CoreDNS pod
IPs at packet-forward time.

So the path is:

```
pod libc resolver
   -> UDP/53 dst=10.96.0.10 (kube-dns Service ClusterIP)
   -> kube-proxy / dataplane DNATs to a CoreDNS pod IP
   -> CoreDNS pod
        - cluster.local names: answered from the in-memory kubernetes
          plugin (a watch on Services and Endpoints)
        - everything else: forwarded per the Corefile's `forward .`
   -> reply travels back, kube-proxy reverses the DNAT, pod sees a
      reply from 10.96.0.10
```

If NodeLocal DNSCache is enabled there's one extra hop on each node —
see section 4.

The three places worth sniffing, in order:

- on the pod's interface, to see what the application asked for and
  what came back;
- on the CoreDNS pod, to see what CoreDNS forwarded upstream;
- on the upstream resolver's interface (node host or VPC), to see what
  the world answered.

```python
>>> sniff(iface="eth0", filter="port 53", count=20).summary()
```

## 2. ndots and search-path expansion

`ndots:5` is the single most surprising thing about DNS in Kubernetes.
The libc resolver counts the dots in the name the application asked
for. If that count is less than `ndots`, the resolver walks the
`search` list first, *then* tries the name as given. `kubernetes.io`
has one dot. With `ndots:5`, that's fewer than 5, so resolution looks
like:

```
kubernetes.io.default.svc.cluster.local   -> NXDOMAIN
kubernetes.io.svc.cluster.local           -> NXDOMAIN
kubernetes.io.cluster.local               -> NXDOMAIN
kubernetes.io                             -> NOERROR, the address
```

Four queries to look up one name. A single `curl example.com` from a
pod can easily issue five DNS packets — and if the pod's DNS path is
slow or lossy, multiplies whatever pain there is by five.

You can see this on the wire from inside the pod. Run the sniffer,
then trigger a lookup from another shell or the IPython escape:

```python
>>> def show(p):
...     if p.haslayer(DNS) and p[DNS].qr == 0:
...         print(p[UDP].sport, p[DNSQR].qname.decode().rstrip("."))
>>> sniff(iface="eth0", filter="udp port 53", prn=show, store=False, timeout=10)
```

Every query in one `getaddrinfo` call shares a UDP source port — the
resolver opens a socket, fires the expanded names sequentially, and
closes it. Group by source port and you've reconstructed one
application-level resolution.

This is what `ndots_trace.py` does for you:

```python
>>> !python3 /app/scripts/dns/ndots_trace.py eth0 20
```

Three ways to dodge the expansion in an application that's making it
hurt:

- write fully-qualified names with a trailing `.` — `example.com.`
  has the resolver skip the search list entirely;
- set `dnsConfig.options` on the pod to lower `ndots` (commonly `2`);
- use `dnsPolicy: None` with an explicit `dnsConfig` and accept
  responsibility for your own search list.

## 3. Measuring DNS latency

When someone says "the app is slow" and you've ruled out the app, the
real question is usually p99, not median. A median of 0.8 ms next to a
p99 of 35 ms is a very different incident from a flat 5 ms across the
board, and the wire view of CoreDNS is the cheapest place to tell
those apart.

The simple loop:

```python
>>> import time
>>> samples = []
>>> for _ in range(100):
...     t0 = time.perf_counter()
...     r = sr1(IP(dst="10.96.0.10")/UDP(dport=53)/
...             DNS(rd=1, qd=DNSQR(qname="kubernetes.default.svc.cluster.local")),
...             timeout=2, verbose=0)
...     samples.append((time.perf_counter() - t0) * 1000 if r else None)
>>> ok = sorted(s for s in samples if s is not None)
>>> ok[len(ok)//2], ok[int(len(ok)*0.99)]
```

Packaged with percentile calculation, a timeout counter, and a useful
header:

```python
>>> !python3 /app/scripts/dns/latency_histogram.py
>>> !python3 /app/scripts/dns/latency_histogram.py example.com 10.96.0.10 500
```

Output:

```
  DNS latency for kubernetes.default.svc.cluster.local via 10.96.0.10 (n=100)
       min: 0.4 ms
       p50: 0.9 ms
       p90: 1.6 ms
       p99: 8.2 ms
       max: 22.1 ms
  timed out: 2/100
```

Two things to read out of that. A p99 an order of magnitude over the
p50 with no timeouts usually points at a single overloaded CoreDNS
replica — fire the same probe at one specific CoreDNS pod IP (skip
the Service) and see if the spread follows. Non-zero timeouts at p99
under modest load usually point at `conntrack` table pressure on the
node, which is its own conversation but starts here.

## 4. NodeLocal DNSCache visibility

If your cluster runs NodeLocal DNSCache, every node has a
`node-local-dns` pod listening on a link-local address — typically
`169.254.20.10` — and pod resolv.conf is rewritten to point there
instead of at the kube-dns Service ClusterIP. The local cache answers
hot entries directly, and forwards misses to CoreDNS over TCP.

Confirming which path your pod is actually using is one sniff:

```python
>>> def show(p):
...     if p.haslayer(DNS):
...         print(p[IP].src, "->", p[IP].dst, "qr=", p[DNS].qr,
...               (p[DNSQR].qname.decode().rstrip(".") if p[DNS].qr == 0
...                else "(reply)"))
>>> sniff(iface="eth0", filter="port 53", prn=show, store=False, count=20)
```

If destinations are `169.254.20.10`, you're on NodeLocal. If they're
the kube-dns ClusterIP (commonly `10.96.0.10`), you're not — either
the cache isn't deployed, or your pod's `dnsPolicy` opted out, or
the DaemonSet isn't healthy on this node.

A NodeLocal-enabled pod that's hitting kube-dns directly is a real
problem. The node-local-dns process on the node configures dummy
interface `nodelocaldns` with the link-local IP and an iptables rule
that redirects pod-originated DNS to it; if either is missing,
traffic falls back to the Service ClusterIP and you've lost the cache
hit-rate benefit without anyone noticing.

## 5. Forwarder behaviour

CoreDNS resolves cluster names locally but forwards everything else.
The Corefile decides where. The default in most installs is:

```
forward . /etc/resolv.conf
```

which means CoreDNS reads the node's `/etc/resolv.conf` at startup
and forwards to whatever nameservers the node uses — frequently a
cloud-provider VPC resolver. Some installs hard-code it:

```
forward . 8.8.8.8 1.1.1.1
```

When the symptom is "external lookups from pods are slow or
intermittent", the question is "where is CoreDNS actually sending
those queries", and you answer it by sniffing on the CoreDNS pod (or
its node):

```python
>>> def fwd(p):
...     if p.haslayer(DNS) and p[DNS].qr == 0:
...         print(p[IP].src, "->", p[IP].dst, p[DNSQR].qname.decode().rstrip("."))
>>> sniff(iface="eth0", filter="udp port 53 and not src host 10.96.0.10",
...       prn=fwd, store=False, count=50)
```

The `not src host 10.96.0.10` half filters out the pod-to-CoreDNS
side and leaves you the CoreDNS-to-upstream side. The destination IPs
on those packets are where your cluster's external DNS is actually
going. If you expected a VPC resolver and you're seeing a public one
(or vice versa), the Corefile and the node resolv.conf are out of
sync.

## 6. NXDOMAIN flood

`ndots:5` plus a misconfigured app config can amplify a single typo
into a burst of NXDOMAIN responses. An application that asks for
`databse-host` (one dot? zero dots — `databse-host` has zero) will,
on every retry, walk the full search list and earn an NXDOMAIN at
each step before hitting the real upstream and getting the final
NXDOMAIN. Four or five NXDOMAINs per app-level lookup, sometimes
hundreds per second under load.

CoreDNS surfaces this on its `/metrics` endpoint as
`coredns_dns_responses_total{rcode="NXDOMAIN"}` rising fast. On the
wire from inside the offending pod:

```python
>>> from collections import Counter
>>> rc = Counter()
>>> def tally(p):
...     if p.haslayer(DNS) and p[DNS].qr == 1:
...         rc[p[DNS].rcode] += 1
>>> sniff(iface="eth0", filter="udp port 53", prn=tally,
...       store=False, timeout=30)
>>> rc       # 0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL
Counter({0: 412, 3: 87, 2: 1})
```

A double-digit percentage of `rcode=3` with a low p99 latency is the
fingerprint. Pair it with `ndots_trace.py` to identify which
application-level name is doing the damage.

## 7. DNS over TCP

DNS classically goes over UDP. Responses larger than 512 bytes — and,
post-EDNS0, larger than whatever the client advertised, typically
1232 or 4096 — set the truncate bit, and the client retries the same
query over TCP/53. AXFR (zone transfers) and most DNS-over-TLS
upstreams also use TCP.

If your sniff filter is `udp port 53`, you miss every TCP fallback,
and the application-level symptom — "lookup works sometimes" — is
mysterious. Use the protocol-agnostic form:

```python
>>> sniff(iface="eth0", filter="port 53", count=50).summary()
```

When a single name keeps falling back to TCP, the answer it returns
is too large for UDP — usually a service with many backends (a long
`A` answer) or DNSSEC-signed responses. CoreDNS's `bufsize` plugin
and the upstream resolver's EDNS0 advertised size together determine
where the cliff is. Sniffing on both UDP and TCP shows you the
fallback in flight; sniffing on UDP alone shows you a partial picture.
