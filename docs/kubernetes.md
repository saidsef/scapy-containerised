# Debugging Kubernetes networking

When pod-to-pod or pod-to-world traffic doesn't work and the YAML looks
fine, the question is usually "which of the half-dozen things between A
and B is silently dropping me". This guide walks through how to use
Scapy from inside the cluster to figure that out.

The shape of the problem is always the same: a packet leaves something,
should arrive somewhere, and doesn't. The layers you peel back — pod
interface, DNS, NetworkPolicy, Service VIP, MTU, kube-proxy, egress NAT
— are roughly the order they tend to fail in. The numbered sections
below follow that order, but you don't have to read them in sequence.
Jump to the layer you suspect.

Everything in this guide runs from the Scapy prompt inside the ttyd
terminal — `python -m scapy.__init__` from the container shell. The
IPython shell escape `!cmd` runs `cmd` in sh without leaving Scapy.

## 1. Getting a Scapy pod where the problem is

The two big choices are where to schedule the pod, and what network
namespace it should be in.

If you're using the Helm chart from this repo, the simplest path is to
deploy with `hostNetwork: true` and privileged mode so the pod sees what
the node sees rather than the CNI-virtualised view:

```sh
helm upgrade --install scapy scapy/scapy -n netdebug --create-namespace \
  --set hostNetwork=true \
  --set securityContext.privileged=true
kubectl -n netdebug port-forward svc/scapy 8080:8080
```

If the bug only reproduces on one node, pin a one-shot pod to that node:

```sh
NODE=$(kubectl get pod broken-pod-xxxxx -o jsonpath='{.spec.nodeName}')
kubectl run scapy-$RANDOM --rm -it --restart=Never \
  --image=docker.io/saidsef/scapy-containerised:latest \
  --overrides='{"spec":{"hostNetwork":true,"nodeName":"'"$NODE"'",
    "containers":[{"name":"scapy","image":"docker.io/saidsef/scapy-containerised:latest",
    "stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}' \
  -- python -m scapy.__init__
```

The `hostNetwork: true` choice has a real consequence: with it on, you
see what the *node* sees, which is mostly what kube-proxy and the CNI
actually route. Without it, you see what the *pod* sees, which is a
virtualised view that hides DNAT and policy enforcement. For most
"packet vanishes" investigations, you want hostNetwork.

To attach to one specific broken pod's network namespace without
redeploying, use an ephemeral debug container:

```sh
kubectl debug -it broken-pod-xxxxx --target=app \
  --image=docker.io/saidsef/scapy-containerised:latest \
  --profile=netadmin
```

`--profile=netadmin` grants `NET_ADMIN`/`NET_RAW` and shares the target
pod's network namespace, which is the right combination for capturing
the pod's actual traffic.

From here, everything runs at the Scapy prompt.

## 2. Is the pod's interface actually working?

This is the cheapest check and the easiest one to forget. If the CNI
failed to wire up the pod's network namespace at sandbox creation, no
amount of NetworkPolicy debugging will help.

```python
>>> conf.ifaces
>>> conf.route
>>> conf.route6
```

What you expect to see in a normal pod:

- An `eth0` (or `cali*`, `lxc*` — depends on CNI) with a real IPv4
  address.
- A default route via the node's cluster gateway.
- IPv6 routes only if you actually have IPv6 configured.

If `eth0` is missing or the default route is wrong, the CNI plugin
failed for this pod. The right place to look next is kubelet logs on the
node, not the application logs.

As a script:

```python
>>> !python3 /app/scripts/k8s/pod_iface.py
```

## 3. Does DNS resolve?

The single most common "Kubernetes networking" symptom is actually a
DNS problem. The fastest way to take DNS out of the picture is to ask
CoreDNS directly, bypassing the libc resolver and `/etc/resolv.conf`
entirely. That tells you whether the *network path* to CoreDNS is fine
and whether CoreDNS itself is answering.

First find the resolver — from a host shell:

```sh
kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}{"\n"}'
```

Then from the Scapy prompt:

```python
>>> resolver = "10.96.0.10"
>>> for name in ("kubernetes.default.svc.cluster.local",
...              "myapp.default.svc.cluster.local",
...              "example.com"):
...     q = IP(dst=resolver)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name))
...     r = sr1(q, timeout=2, verbose=0)
...     if r and r.haslayer(DNS):
...         print(f"{name}: rcode={r[DNS].rcode}, answers={r[DNS].ancount}")
...     else:
...         print(f"{name}: no reply")
```

What the output means:

- **No reply at all** — CoreDNS is dead, or a NetworkPolicy is blocking
  egress from your namespace to kube-system. `kubectl -n kube-system get
  pods -l k8s-app=kube-dns` is the next step.
- **rcode=3 (NXDOMAIN)** for an internal name — the resolver could
  answer, but the name isn't right. Usually a wrong `search` order in
  `/etc/resolv.conf` or a typo'd namespace.
- **rcode=2 (SERVFAIL)** for external names — CoreDNS is up but its
  upstream is broken. The Corefile is where you go next.
- **Answers come back but the app still can't connect** — DNS is not your
  problem. Move on.

As a script:

```python
>>> !python3 /app/scripts/k8s/dns_check.py 10.96.0.10 \
...   kubernetes.default.svc.cluster.local \
...   myapp.default.svc.cluster.local
```

## 4. Is something silently dropping traffic?

NetworkPolicy doesn't return errors. When a policy denies a flow, the
packet is just gone — no RST, no ICMP unreachable, nothing. Symptom on
the client side is a TCP connect that hangs until the application timeout.

The cleanest way to confirm a black-hole drop is to sniff for the
specific flow on the source node. From a Scapy pod with `hostNetwork:
true`, scheduled on the same node as the source pod:

```python
>>> sniff(iface="any",
...       filter="host 10.244.1.5 and host 10.244.2.7",
...       prn=lambda p: print(p.summary()), count=20, timeout=15)
```

What you see decides the next move:

- SYN goes out, no SYN/ACK, no ICMP back → silent drop. Either
  NetworkPolicy, or a CNI bug. `kubectl get netpol -A` and read every
  policy that selects the source or destination pod.
- SYN goes out, RST/ACK back from the dest pod's IP → the application
  refused the connection. Not a network problem.
- SYN goes out, ICMP unreachable back → kube-proxy or iptables rejected.
  Rarer.
- No SYN from the source at all → the application never made the call.
  Look at the app, not the network.

As a script:

```python
>>> !python3 /app/scripts/k8s/pair_sniff.py 10.244.1.5 10.244.2.7
```

## 5. Is DNAT happening for a Service ClusterIP?

When you connect to a Service ClusterIP, the kernel rewrites the
destination address to a real pod IP via DNAT, and the reply comes back
from that pod IP. If both directions only ever show the ClusterIP and
you never see a pod address, kube-proxy isn't programming its rules
correctly.

```python
>>> sniff(iface="any",
...       filter="tcp port 443 and host 10.96.123.45",
...       prn=lambda p: print(p[IP].src, "->", p[IP].dst, p[TCP].flags),
...       count=10)
```

If you see DNAT happen — outgoing has dst=ClusterIP, return has
src=pod-ip — kube-proxy is fine and the problem is downstream. If both
directions show ClusterIP, look at the kube-proxy pods on the node and
their logs.

As a script:

```python
>>> !python3 /app/scripts/k8s/service_dnat.py 10.96.123.45 443
```

## 6. MTU and path-MTU

The pattern that points at MTU is: small requests succeed, large
requests hang. TLS handshakes (small) complete; the first big response
gets stuck. CNIs that tunnel — VXLAN, IPIP, WireGuard — add overhead, and
if the pod MTU isn't dropped to account for it, traffic egress falls off
a cliff for any packet over the underlay MTU.

The DF-bit ICMP probe walks down from typical MTU values and tells you
which size is the largest that gets through:

```python
>>> for size in (1500, 1450, 1400, 1280, 1024, 576):
...     r = sr1(IP(dst="10.0.0.5", flags="DF")/ICMP()/("X" * (size - 28)),
...             timeout=2, verbose=0)
...     print(size, "->", "ok" if r else "no reply (likely PMTU)")
```

If 1500 fails but 1450 works, you have a tunnel overhead problem. Check
`ip link show eth0` in the pod and on the node — both ends of the
tunnel need their MTU set consistently.

As a script:

```python
>>> !python3 /app/scripts/k8s/pmtu.py 10.0.0.5
```

## 7. Is kube-proxy load-balancing?

When a Service has multiple backends, kube-proxy should spread
connections across them. If only one backend ever answers and the
Service has three endpoints, either there's session affinity in play
(`spec.sessionAffinity: ClientIP`) or kube-proxy is in IPVS mode using
`sh` (source-hash) scheduling, which deterministically picks the same
backend for the same source.

```python
>>> ans, _ = sr(IP(dst="10.96.123.45")/TCP(sport=range(40000, 40050),
...                                        dport=80, flags="S"),
...             timeout=2, verbose=0)
>>> backends = {r[1][IP].src for r in ans if r[1][TCP].flags == "SA"}
>>> print(len(backends), "backends answered:", backends)
```

```python
>>> !python3 /app/scripts/k8s/lb_spread.py 10.96.123.45 80
```

## 8. What egress IP do we look like from outside?

"We're allowlisted but the SaaS still sees a different IP." OpenDNS has
a special record that returns your source IP, which is exactly the IP
the public internet sees after any NAT in front of you.

```python
>>> r = sr1(IP(dst="resolver1.opendns.com")/UDP(dport=53)/
...         DNS(rd=1, qd=DNSQR(qname="myip.opendns.com", qtype="A")),
...         timeout=3, verbose=0)
>>> print("Egress IP:", r[DNS].an.rdata)
```

Compare with whatever the SaaS provider has allowlisted. Common
mismatches: the cluster has multiple NAT gateways and nodes go through
different ones; the egress changed recently and the allowlist is stale;
egress is configured per-namespace via a Cilium / Calico egress gateway
that you forgot about.

As a script:

```python
>>> !python3 /app/scripts/k8s/egress_ip.py
```

## 9. Capturing from a pod when kubectl debug isn't available

Sometimes you don't have `kubectl debug`, but you do have SSH to the
node. You can capture from a specific pod's network namespace using
`nsenter`:

```sh
PID=$(crictl inspect $(crictl ps -q --name broken-pod) | jq -r .info.pid)
nsenter -t $PID -n tcpdump -i eth0 -w /tmp/broken.pcap
```

Then copy the pcap to a Scapy pod and dig in from the Scapy prompt:

```python
>>> pkts = rdpcap("/tmp/broken.pcap")
>>> pkts.filter(lambda p: TCP in p and p[TCP].flags == "S").summary()
```

Or, if you just want a fast read of every DNS name the pod tried to
resolve:

```python
>>> !python3 /app/scripts/sniffing/pcap_dns.py /tmp/broken.pcap
```

## Things that look like networking and aren't

A few patterns that land in the network-team queue but aren't network
problems. Worth keeping in mind so you don't burn time chasing them.

The JVM's DNS cache is, by default, infinite for successful resolutions.
If a service IP changes (rolling Service recreations are the classic
trigger), Java clients keep using the old one. Looks like "service
discovery is stale". Not a network bug.

`localhost` from a pod with `hostNetwork: true` is the *node's*
localhost, not the pod's. People wire up health checks against
127.0.0.1 and are surprised when the wrong process answers.

IPv6 enabled in the container but not in the cluster is a common
slowness pattern. `getaddrinfo` returns the AAAA record first, the
connection attempt hangs until it gives up and falls back to IPv4.
Looks like an intermittent slowness in one app.

`externalTrafficPolicy: Local` on a Service plus a LoadBalancer that
hashes to a node without a backend equals dropped traffic. From outside
the cluster it looks like a black hole; from inside you'd see no
problem at all. The Service's endpoint distribution across nodes is
worth a look when this pattern appears.
