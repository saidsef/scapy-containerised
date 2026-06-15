# docs

Practical notes for using this container day to day. Written for people on
call, not as a Scapy tutorial — read the
[official docs](https://scapy.readthedocs.io) if you want the full
reference.

| Guide | When to read it |
|---|---|
| [recon.md](recon.md) | "What is on this network and what does it look like?" |
| [sniffing.md](sniffing.md) | "Something is hitting this host, what is it?" |
| [routes.md](routes.md) | "Why is the packet going (or not going) out that interface?" |
| [kubernetes.md](kubernetes.md) | "Pod A can't talk to pod B and the YAML looks fine." |

## How the workflow works

Every guide here assumes you're sitting in **ttyd at http://localhost:8080**.
That gives you a plain `sh` prompt inside the container, with everything
preinstalled and the helper scripts already on disk at `/app/scripts/`.

You'll bounce between two modes:

1. **Run a script.** Most workflows in these guides are one command:

   ```sh
   python3 /app/scripts/recon/arp_sweep.py 10.0.0.0/24
   ```

   Each script takes positional args and prints results. No flags, no
   config files. Read the docstring at the top of any script if you want
   to know what it accepts.

2. **Drop into the Scapy REPL.** For poking, exploring, or stitching
   commands together:

   ```sh
   scapy
   >>> arping("10.0.0.0/24")
   ```

   IPython is the backing shell, so tab completion and `?` work. To load
   one of the scripts as a helper:

   ```python
   >>> exec(open("/app/scripts/routes/whereis.py").read())
   ```

   Or just call the building blocks directly — the scripts are small and
   readable, copy what you need.

## Getting to the prompt

Out of the box:

```sh
docker run -d --net=host --privileged \
    -v $PWD/data:/data \
    saidsef/scapy-containerised:latest
open http://localhost:8080
```

Helm chart in this repo:

```sh
helm upgrade --install scapy scapy/scapy -n scapy --create-namespace
kubectl -n scapy port-forward svc/scapy 8080:8080
open http://localhost:8080
```

If you don't want the browser at all, skip ttyd and exec straight in:

```sh
docker exec -it <container> scapy
kubectl -n scapy exec -it deploy/scapy -- scapy
```

## Ground rules

- Capturing traffic needs `CAP_NET_RAW` and `CAP_NET_ADMIN`. In Docker
  that's `--privileged` or `--cap-add=NET_RAW --cap-add=NET_ADMIN`. In
  Kubernetes it's `securityContext.capabilities.add: [NET_RAW, NET_ADMIN]`
  plus, almost always, `hostNetwork: true` if you want to see what the
  node sees instead of what the pod sees.
- `sniff()` blocks until `count` or `timeout` is reached. Set one of them
  or you'll sit there waiting for a prompt that never returns.
- Scapy's `send`/`sr` work at L3. For raw frames (ARP, STP, anything
  pre-IP), use `sendp`/`srp`/`sniff(iface=...)`.
- Files you write to `/tmp` survive until the container restarts. Copy
  them out with `docker cp` or `kubectl cp` when you're done.

## Script index

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
```
