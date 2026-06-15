# NetworkPolicy from the wire

This guide is about understanding what a Kubernetes NetworkPolicy actually
does to a packet, and using Scapy to confirm or refute "the policy is the
problem" without writing more YAML. The brief mention in
`docs/kubernetes.md` covers the basics; this is the deeper read.

All examples assume you're at the Scapy prompt — `python -m scapy.__init__`
from the ttyd terminal at http://localhost:8080 — and that the pod is
running with the labels you want to test. For node-side inspection you
also want `hostNetwork: true` and the `NET_ADMIN` / `NET_RAW`
capabilities.

## 1. The model in one paragraph

NetworkPolicy is additive deny. With no policy in a namespace, every
pod-to-pod and pod-to-external flow is allowed in both directions. The
moment the first policy in the namespace selects a given pod for a given
direction (ingress, egress, or both), that pod switches to default-deny
for that direction, and the rules in the policy enumerate the *only*
traffic that is now allowed. Add a second policy that selects the same
pod, and the allowed set is the union of both policies' rules — they
"OR", they do not "AND". Almost every NetworkPolicy bug in the wild
comes from someone reasoning about the rules as if they composed
intersectively. They don't.

## 2. How a denied packet looks on the wire

CNI enforcement is silent. No RST, no ICMP admin-prohibited, no
indication of any kind reaches the source. The TCP `connect()` call
hangs until the kernel gives up. From a sniff on the source side, you
see your SYN go out, no SYN/ACK come back, and nothing else — exactly
the same shape as a host being powered off mid-flight.

Distinguishing the four real outcomes is what Scapy is for here. Run
`sr1` with a short timeout and read the response:

```python
>>> from scapy.all import sr1, IP, TCP, ICMP
>>> r = sr1(IP(dst="10.244.2.7")/TCP(dport=8080, flags="S"),
...         timeout=2, verbose=0)
```

Four cases:

- `r` is a `TCP` with `flags == "SA"` — the path is open and the app
  accepted the SYN. Policy allows, listener present.
- `r` is a `TCP` with `flags == "RA"` (RST/ACK) — the path is open, the
  packet reached the destination kernel, and there is no listener on
  that port. Not a policy issue; the app isn't bound.
- `r` is an `ICMP` packet (usually type 3, code 13 "admin prohibited",
  or code 10 "host admin prohibited") — something in path is explicitly
  rejecting. Most often kube-proxy `REJECT` rules, sometimes a firewall.
- `r` is `None` — silent drop. NetworkPolicy is the prime suspect,
  followed by CNI blackhole and broken routing.

A `None` doesn't *prove* it's NetworkPolicy, but it narrows the
hypothesis hard. The classifier script in section 7 wraps this:

```python
>>> !python3 /app/scripts/netpol/probe.py 10.244.2.7 8080
>>> !python3 /app/scripts/netpol/probe.py 10.244.2.7 8080 5 1
```

## 3. Testing a policy without trial-and-error

The expensive way to validate a policy is to apply it to production
workloads and find out by pager. The cheap way is to run your Scapy pod
with the labels the policy will select, and probe the same destinations
the real workload would.

Suppose you're about to apply a policy that selects
`app=payments,tier=api` in `namespace=prod` and is supposed to allow
egress only to `app=db,tier=primary` on TCP/5432, plus DNS to
kube-system. Before applying it for real, run the Scapy pod with those
labels in a non-prod namespace with the same intended policy mirrored
into it. From the Scapy prompt:

```python
>>> from scapy.all import sr1, IP, TCP, DNS, DNSQR, UDP
>>> # should succeed
>>> sr1(IP(dst="<db-pod-ip>")/TCP(dport=5432, flags="S"),
...     timeout=2, verbose=0)
>>> # should silently drop
>>> sr1(IP(dst="<db-pod-ip>")/TCP(dport=6379, flags="S"),
...     timeout=2, verbose=0)
>>> # should silently drop
>>> sr1(IP(dst="<unrelated-pod-ip>")/TCP(dport=5432, flags="S"),
...     timeout=2, verbose=0)
>>> # should succeed
>>> sr1(IP(dst="<kube-dns-ip>")/UDP(dport=53)/DNS(rd=1,
...     qd=DNSQR(qname="kubernetes.default")), timeout=2, verbose=0)
```

For ingress, flip the direction: deploy a tiny listener (a one-shot
`nc -l -p 8080`, or use the test harness in your stack) in the Scapy
pod, then probe it from a pod with the labels the policy is meant to
allow and from one with labels it is meant to deny. Same four-outcome
classification applies.

The single rule that catches most bugs early: if a probe that you
expected to be *allowed* returns `None`, you have an error in your
policy (or a CNI bug). If a probe that you expected to be *denied*
returns `SA` or `RA`, you have an error in your policy. Neither needs
the production workload to discover.

## 4. Common misconfigurations

These are the bugs that show up over and over.

**Empty `from:` versus missing `from:`.** A one-character YAML difference
that inverts the meaning.

```yaml
# allows from any pod in any namespace (no from = no restriction)
- ports:
  - port: 8080
```

```yaml
# allows from nothing — equivalent to deny for this port
- from: []
  ports:
  - port: 8080
```

If you wrote `from:` and then never added entries beneath it because you
were going to "fix it later", you have written deny.

**`podSelector: {}` matches everything in the namespace.** People read
the empty map as "match nothing" and write it as a no-op. It is a
match-all selector, which is exactly what you want at the top level of
a namespace-wide default-deny policy and exactly *not* what you want
inside an `ingress.from.podSelector`.

**Egress policy on the source without ingress on the destination.** You
allow egress from `app=payments` to `app=db` on 5432. The connection
still fails. Look at `namespace=db` — if there is a default-deny
ingress policy there and no rule allows traffic from `app=payments`,
the destination drops your SYN. From the Scapy pod in the source
namespace this presents as `None` — exactly the same as "source egress
denied". The classifier in section 8 sees one direction of traffic and
will tell you the SYN left the source; if the destination namespace is
the problem, the next step is to run a sniff inside the destination
namespace and look for the incoming SYN.

**Combined `namespaceSelector` and `podSelector` is AND, not OR.** When
both appear under the same `from:` or `to:` entry, the rule matches
pods that satisfy both. Two separate entries under `from:` would OR.

```yaml
# AND: pods labelled team=payments IN namespaces labelled env=prod
from:
- namespaceSelector: {matchLabels: {env: prod}}
  podSelector: {matchLabels: {team: payments}}
```

```yaml
# OR: any pod in env=prod namespaces, plus any pod labelled team=payments anywhere
from:
- namespaceSelector: {matchLabels: {env: prod}}
- podSelector: {matchLabels: {team: payments}}
```

These have very different blast radii.

**Forgetting DNS to kube-system.** This is the single most frequent
single mistake. A default-deny egress policy on an app namespace breaks
name resolution before it breaks anything else, and the application
logs read "connection timed out to <hostname>" without mentioning DNS.
Every egress policy needs:

```yaml
- to:
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: kube-system
  ports:
  - port: 53
    protocol: UDP
  - port: 53
    protocol: TCP
```

You can confirm DNS is the failing layer from Scapy in a few seconds:

```python
>>> sr1(IP(dst="<kube-dns-ip>")/UDP(dport=53)/DNS(rd=1,
...     qd=DNSQR(qname="kubernetes.default")), timeout=2, verbose=0)
```

`None` here and `SA` to the actual destination IP means DNS is the
broken hop.

## 5. Watching the CNI enforcement layer

CNIs enforce at the kernel. Calico writes iptables or eBPF, Cilium
writes eBPF programs attached to interfaces. From a Scapy pod with
`hostNetwork: true` you can sniff the host's CNI interfaces directly
and find out which side of the cluster is dropping.

```python
>>> sniff(iface="cali12abc34de", count=20).summary()    # Calico veth
>>> sniff(iface="cilium_host", count=20).summary()      # Cilium
>>> sniff(iface="cni0", count=20).summary()             # bridge plugins
>>> sniff(iface="flannel.1", count=20).summary()        # Flannel VXLAN
```

The decision tree from the pair sniffer:

```python
>>> !python3 /app/scripts/k8s/pair_sniff.py 10.244.1.5 10.244.2.7 any 30
```

- The source-side pod veth shows the SYN, the source node's egress
  interface (eth0, the VXLAN device, etc.) does *not* show it leaving:
  source-node enforcement dropped it. Look at the policy that selects
  the source pod.
- Source egress interface shows the SYN leaving, destination node's
  ingress interface shows it arriving, destination pod veth does *not*:
  destination-node enforcement dropped it. Look at the policy that
  selects the destination pod.
- All interfaces show the SYN, including the destination pod veth, but
  no SYN/ACK ever comes back: the destination pod received the packet
  and didn't reply. That's an application problem, not a policy
  problem.

This is the single most useful diagnostic in a "is it the network or
the app" argument, because both teams can read the output together.

## 6. The default-deny gotcha

The smallest NetworkPolicy that has any effect is the one that denies
everything:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

`podSelector: {}` matches every pod in the namespace, the policy lists
both directions, and there are no `ingress:` or `egress:` rules — so
nothing is allowed. People apply this and then layer narrower policies
on top to permit specific traffic. The trap is when someone applies the
default-deny and forgets the narrower policies, or applies them in the
wrong namespace.

Confirm the deny is doing what it claims from outside the namespace,
using the Scapy pod in a different namespace:

```python
>>> from scapy.all import sr1, IP, TCP
>>> # to any pod in the locked-down namespace
>>> r = sr1(IP(dst="<pod-in-app-ns>")/TCP(dport=8080, flags="S"),
...         timeout=2, verbose=0)
>>> print("ALLOWED" if r and r.haslayer(TCP) and r[TCP].flags == "SA"
...                else "DENIED" if r is None
...                else "OTHER")
```

`DENIED` is what you want for a destination the policy should be
covering. `OTHER` (an ICMP unreachable, an RST) means the packet
reached the kernel and something other than the policy answered — the
policy isn't applying to that pod. Check the selector.

## 7. Classifying a single probe

`probe.py` sends TCP SYN probes and prints which of the four outcomes
each one falls into. The aggregate over multiple probes is the
diagnosis you want — a single `None` could be packet loss, three out
of three `None` is policy or blackhole.

```python
>>> !python3 /app/scripts/netpol/probe.py 10.244.2.7 8080
>>> !python3 /app/scripts/netpol/probe.py 10.244.2.7 8080 5
>>> !python3 /app/scripts/netpol/probe.py 10.244.2.7 8080 3 1
```

Output:

```
10.244.2.7:8080 -> 3/3 silently dropped (NetworkPolicy or CNI blackhole)
10.244.2.7:8080 -> 3/3 open (SYN/ACK)
10.244.2.7:8080 -> 3/3 refused (RST)
10.244.2.7:8080 -> 3/3 rejected (ICMP type=3 code=13)
10.244.2.7:8080 -> 2/3 open, 1/3 silently dropped
```

Mixed results usually mean there's a race or the destination is behind
a Service with multiple endpoints and one of them is misconfigured.

## 8. Classifying a flow from a passive sniff

When you can't actively probe — for example you want to diagnose what
the real application is doing without injecting traffic — sniff the
flow and let the classifier tell you which direction is broken and at
what layer.

```python
>>> !python3 /app/scripts/netpol/drop_classify.py 10.244.1.5 10.244.2.7 8080
>>> !python3 /app/scripts/netpol/drop_classify.py 10.244.1.5 10.244.2.7 8080 60
```

It watches `host <src> and host <dst>` on `any` for the timeout, then
prints one line:

```
bidirectional ok (SYN from src, SYN/ACK from dst, 14 pkts total)
src->dst broken, no response from dst (SYN seen, no SYN/ACK, 3 pkts)
dst refused (SYN from src, RST from dst, 2 pkts)
src never sent (0 SYN from src, 0 pkts)
```

"`src never sent`" is the one that surprises people — it means the
application never called `connect()`, which usually means DNS failed
earlier, the config is pointing somewhere else, or the call is gated
behind a code path that didn't execute. None of those are network
problems.
