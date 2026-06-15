# Debugging Kubernetes networking

The pattern is always the same: a pod can't reach something it should
reach, or it's reaching something it shouldn't. By the time it lands on
you, three people have already said "DNS is fine" and one has said "must
be the NetworkPolicy" without checking.

This page is the list of checks I actually run, in order. Each one is a
script you run from the ttyd prompt at **http://localhost:8080**.

## 0. Get a Scapy pod where the problem is

Helm chart in this repo, scheduled with host networking so the pod sees
what the node sees:

```sh
helm upgrade --install scapy scapy/scapy -n netdebug --create-namespace \
  --set hostNetwork=true \
  --set securityContext.privileged=true
kubectl -n netdebug port-forward svc/scapy 8080:8080
```

One-shot pod pinned to a specific node (useful when the bug only repros
on one node):

```sh
NODE=$(kubectl get pod broken-pod-xxxxx -o jsonpath='{.spec.nodeName}')
kubectl run scapy-$RANDOM --rm -it --restart=Never \
  --image=docker.io/saidsef/scapy-containerised:latest \
  --overrides='{"spec":{"hostNetwork":true,"nodeName":"'"$NODE"'",
    "containers":[{"name":"scapy","image":"docker.io/saidsef/scapy-containerised:latest",
    "stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}' \
  -- sh
```

`hostNetwork: true` is the key bit. Without it you see what the *pod*
sees, which is a CNI-virtualised view. With it you see what the *node*
sees, which is what most CNIs actually route.

To attach to one specific broken pod's network namespace without
redeploying anything, use an ephemeral debug container:

```sh
kubectl debug -it broken-pod-xxxxx --target=app \
  --image=docker.io/saidsef/scapy-containerised:latest \
  --profile=netadmin
```

`--profile=netadmin` grants `NET_ADMIN`/`NET_RAW` and shares the target
pod's network namespace — exactly what you want.

From here on, everything runs from inside the Scapy pod via ttyd.

## 1. Is the pod's interface up and routing sane?

```sh
python3 /app/scripts/k8s/pod_iface.py
```

What you expect in a normal pod:

- `eth0` (or `cali*`, `lxc*`, etc. depending on CNI) with a /32 or /24
- A default route via the node's cluster gateway
- IPv6 routes only if you actually have IPv6

If `eth0` is missing or the default route is wrong, the CNI failed during
pod sandbox setup. Look at kubelet logs on the node, not at the
application.

## 2. Does DNS actually resolve?

This is the single most common "Kubernetes networking" bug and it is
almost never networking. Find your resolver:

```sh
kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}{"\n"}'
```

Then hand-roll a query that bypasses the libc resolver and the pod's
`/etc/resolv.conf` entirely — this tells you whether the network path to
CoreDNS is fine:

```sh
python3 /app/scripts/k8s/dns_check.py 10.96.0.10 \
  kubernetes.default.svc.cluster.local \
  myapp.default.svc.cluster.local \
  example.com
```

Interpret the output:

- **No reply at all** → CoreDNS pod is dead, or a NetworkPolicy blocks
  egress to kube-system. Check `kubectl -n kube-system get pods -l k8s-app=kube-dns`.
- **rcode=3 (NXDOMAIN) for an internal name** → wrong `search` order in
  `/etc/resolv.conf`, or wrong namespace in the name.
- **rcode=2 (SERVFAIL) for external names** → CoreDNS upstream is broken.
  Look at the Corefile.
- **Answers come back but the app still can't connect** → not DNS.
  Move on.

## 3. NetworkPolicy: is something silently dropping you?

NetworkPolicy is invisible from inside the pod. Symptom: TCP connect
hangs with no RST, no ICMP, nothing. From a Scapy pod with
`hostNetwork: true` **on the same node as the source pod**:

```sh
python3 /app/scripts/k8s/pair_sniff.py <source-pod-ip> <dest-pod-ip>
```

What you see tells you who's dropping:

- SYN out, no SYN/ACK, no ICMP → NetworkPolicy or CNI dropping silently.
  Run `kubectl get netpol -A` and read them.
- SYN out, RST/ACK back → the dest app refused the connection. Not a
  network problem.
- SYN out, ICMP unreachable back → kube-proxy / iptables rejected (rare).
- No SYN from the source at all → the app never made the call. Look at
  the app.

## 4. Service VIP: who is the packet actually going to?

```sh
python3 /app/scripts/k8s/service_dnat.py 10.96.123.45 443
```

You should see traffic to the ClusterIP go out and a reply come back from
a real pod IP — that's the kernel rewriting dst via DNAT. If both
directions only ever show the ClusterIP and never a pod IP, kube-proxy
isn't programming its rules. Check
`kubectl -n kube-system get pods -l k8s-app=kube-proxy` and its logs.

## 5. MTU / path-MTU problems

Symptoms: small requests work, large requests hang. TLS handshake
completes, the first big response gets stuck.

```sh
python3 /app/scripts/k8s/pmtu.py 10.0.0.5
```

CNIs that tunnel (VXLAN, IPIP, WireGuard) add overhead. If your
underlying network MTU is 1500, your pod MTU usually needs to be 1450 or
lower. Cross-check with `ip link show eth0` inside the pod and on the
node.

## 6. Is kube-proxy actually load-balancing?

```sh
python3 /app/scripts/k8s/lb_spread.py 10.96.123.45 80
```

If only one backend answers and the Service has 3 endpoints, suspect
session affinity (`spec.sessionAffinity: ClientIP`) or kube-proxy in ipvs
mode with `sh` (source-hash) scheduling.

## 7. Outbound through the NAT gateway

"My pod can reach the internet but the SaaS provider sees the wrong IP."

```sh
python3 /app/scripts/k8s/egress_ip.py
```

That's the source IP the public internet sees. Compare it with the SaaS
allowlist.

## 8. Capture from a specific pod's namespace without kubectl debug

If `kubectl debug` isn't available and you can SSH to the node:

```sh
PID=$(crictl inspect $(crictl ps -q --name broken-pod) | jq -r .info.pid)
nsenter -t $PID -n tcpdump -i eth0 -w /tmp/broken.pcap
```

Copy the pcap into a Scapy pod and analyse there:

```sh
# inside the Scapy ttyd shell
python3 /app/scripts/sniffing/pcap_dns.py /tmp/broken.pcap
```

Or open it interactively:

```python
pkts = rdpcap("/tmp/broken.pcap")
pkts.filter(lambda p: TCP in p and p[TCP].flags == "S").summary()
```

## Things that look like networking and aren't

- **JVM DNS cache** (default infinite TTL) → looks like "service
  discovery is stale". Not a network bug.
- **`localhost` from a pod with `hostNetwork: true`** → that's the
  *node*'s localhost, not the pod's. Trips people up constantly.
- **IPv6 enabled in the container, disabled in the cluster** →
  `getaddrinfo` returns AAAA first, the connection hangs for the IPv4
  fallback.
- **Service `externalTrafficPolicy: Local`** and you're talking to a node
  without a backend → packets get dropped, traffic is a black hole from
  outside, fine from inside.
