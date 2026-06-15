# Guides

These guides walk you through using Scapy inside this container for
network reconnaissance, packet capture, route inspection, and Kubernetes
debugging. They are not a Scapy tutorial — the
[official Scapy docs](https://scapy.readthedocs.io) cover the language
itself. What's here is the practical "I'm staring at a problem, how do I
get an answer" view.

| Guide | What it covers |
|---|---|
| [recon.md](recon.md) | Finding hosts, scanning ports, tracing paths, fingerprinting OS |
| [sniffing.md](sniffing.md) | Live decode, pcap files, decoding HTTP and TLS, plotting traffic |
| [routes.md](routes.md) | Understanding which interface a packet takes, ARP, multi-homed hosts |
| [kubernetes.md](kubernetes.md) | Debugging pod-to-pod and pod-to-world connectivity problems |
| [network-policy.md](network-policy.md) | Reading the NetworkPolicy model from the wire, testing rules before they ship |
| [service-discovery.md](service-discovery.md) | Mapping who-calls-whom from real traffic, top talkers |
| [service-mesh.md](service-mesh.md) | Istio/Linkerd sidecar traffic, mTLS, SPIFFE identity, 503 NR/UF/UH |
| [coredns.md](coredns.md) | CoreDNS path, `ndots:5` expansion, latency distribution, NodeLocal cache |
| [cni-overlay.md](cni-overlay.md) | VXLAN/Geneve/IPIP/WireGuard underlay vs overlay traffic, MTU |

## Where you'll be working

Every example in these guides assumes you have the ttyd web terminal open
at **http://localhost:8080** and you're already inside the Scapy shell.
From the ttyd terminal:

```sh
python -m scapy.__init__
```

You'll see the Scapy banner and an IPython prompt:

```
                                      
                     aSPY//YASa       
             apyyyyCY//////////YCa       |
            sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
 ayp ayyyyyyySCP//Pp           syY//C    | Version 2.7.0
 ...

>>>
```

Everything from there is Python. When a guide says "run this", paste it
at the `>>>` prompt. Tab completion and `?` work — `arping?` shows the
function signature and docstring, `arping??` shows the source.

## Two ways to use the guides

Each guide gives you concrete snippets you can paste straight into the
Scapy shell. The same workflows are also packaged as standalone scripts
under `/app/scripts/` for when you want to run one as a single command.

To launch a script from the Scapy shell without leaving it, use the
IPython shell escape:

```python
>>> !python3 /app/scripts/recon/arp_sweep.py 10.0.0.0/24
```

The `!` runs the rest of the line in `sh` and prints output back into
your Scapy session. Useful for one-shot captures or scans where you
don't need the result as a Python value.

If you do want the result in your session — for example to filter, slice,
or feed into another Scapy call — paste the equivalent snippet directly:

```python
>>> ans, _ = arping("10.0.0.0/24", verbose=0)
>>> ips = [r[1].psrc for r in ans]
```

The scripts are short and readable; if a guide refers to one, opening it
will show you exactly what it does:

```python
>>> !cat /app/scripts/recon/arp_sweep.py
```

## Getting to ttyd in the first place

For local development:

```sh
docker run -d --net=host --privileged \
    -v $PWD/data:/data \
    saidsef/scapy-containerised:latest
open http://localhost:8080
```

Via the Helm chart in this repo:

```sh
helm upgrade --install scapy scapy/scapy -n scapy --create-namespace
kubectl -n scapy port-forward svc/scapy 8080:8080
open http://localhost:8080
```

If you don't want a browser session, you can exec straight into the
container and skip ttyd:

```sh
docker exec -it <container> python -m scapy.__init__
kubectl -n scapy exec -it deploy/scapy -- python -m scapy.__init__
```

## A few things to know before you start

Capturing traffic needs `CAP_NET_RAW` and `CAP_NET_ADMIN`. The Docker
flag is `--privileged` or `--cap-add=NET_RAW --cap-add=NET_ADMIN`. In
Kubernetes, set `securityContext.capabilities.add: [NET_RAW, NET_ADMIN]`
and — almost always — `hostNetwork: true` if you want to see what the
node sees instead of what the pod sees. The Helm chart in this repo
exposes both as values.

`sniff()` blocks until `count` or `timeout` is reached. If you call it
with neither, your prompt won't come back. The guides always set one or
the other; if you start improvising, remember to do the same.

Scapy's `send` and `sr` work at layer 3 — they fill in the routing for
you. For raw frames (ARP, STP, anything pre-IP) reach for `sendp`, `srp`,
and `sniff(iface=...)` instead.

Files written to `/tmp` survive until the container restarts. Copy them
out from a host shell with `docker cp <container>:/tmp/foo .` or
`kubectl -n <ns> cp <pod>:/tmp/foo ./foo`.

## What's in scripts/

If you want to skim the available scripts before reading the guides:

```
scripts/
  recon/
    arp_sweep.py          who's on this L2
    icmp_sweep.py         ping sweep across L3
    syn_scan.py           TCP SYN port scan with RST teardown
    traceroute_world.py   traceroute + GeoIP world map PDF
    passive_os.py         TTL + window OS guess from inbound SYNs
    dns_probe.py          common-subdomain probe via one resolver
    raw_dump.py           hexdump payloads on an unknown TCP port
  sniffing/
    live_summary.py       one-line summary per packet
    to_pcap.py            stream capture to disk
    pcap_dns.py           extract DNS queries from a pcap
    http_requests.py      decode plaintext HTTP requests
    tls_sni.py            extract SNI from TLS ClientHello
    tls_handshake.py      full TLS handshake (cipher, cert, ALPN, alerts)
    tcp_health.py         per-flow retransmits, RTT, zero-windows
    plot_sizes.py         packet-size histogram PNG
    tcp_sessions.py       naive stream reassembly
  routes/
    whereis.py            route + ARP + ping for one IP
  k8s/
    pod_iface.py          dump interfaces + routes
    dns_check.py          hand-rolled DNS at kube-dns
    pair_sniff.py         watch traffic between two IPs
    service_dnat.py       verify DNAT for a Service ClusterIP
    pmtu.py               DF-bit ICMP MTU probe
    lb_spread.py          count distinct backends behind a ClusterIP
    egress_ip.py          ask OpenDNS for your egress NAT IP
  netpol/
    probe.py              classify outcome of SYN probes (open/refused/rejected/drop)
    drop_classify.py      verdict on a flow between two endpoints
  discovery/
    conn_graph.py         directed graph of who initiates TCP to whom
    talkers.py            top talkers by bytes (both directions folded)
  mesh/
    sidecar_traffic.py    loopback view of envoy/linkerd-proxy ports
    spiffe_id.py          pull SPIFFE URIs from TLS cert SANs
  dns/
    latency_histogram.py  min/p50/p90/p99/max DNS latency for N queries
    ndots_trace.py        observe search-path expansion per src port
  cni/
    vxlan_decode.py       dissect VXLAN-encapsulated inner packets
    geneve_decode.py      dissect Geneve-encapsulated inner packets
```
