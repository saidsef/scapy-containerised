# Service mesh debugging

This guide is about debugging Istio and Linkerd traffic from inside a
meshed pod, or from a `hostNetwork: true` Scapy pod scheduled on the same
node as the workload you're chasing. The mesh hides a lot. Scapy is one
of the few tools that lets you see what's actually happening on both
sides of the sidecar at once.

`istioctl proxy-config` and `linkerd diagnostics` are faster when you
want to read configuration. The case for Scapy is that the configuration
is rarely the thing that's broken — it's the interaction between the
application, the sidecar, and the remote sidecar that's broken. You need
to see bytes on the wire and on loopback at the same time.

Everything below assumes you're at the Scapy prompt — `python -m scapy.__init__`
from the ttyd terminal at http://localhost:8080.

## 1. The shape of mesh traffic

Without this mental model you'll spend hours debugging the wrong thing.

In a meshed pod there are at least two processes that matter: your
application and the sidecar proxy (Envoy for Istio, linkerd-proxy for
Linkerd). iptables rules in the pod's network namespace redirect traffic
to and from the application through the sidecar.

For Istio:

- Outbound from the app is redirected to `127.0.0.1:15001`. The sidecar
  picks the upstream cluster from the original destination and dials out.
- Inbound to the pod is redirected to `127.0.0.1:15006`. The sidecar
  terminates mTLS, then forwards plaintext to the application's listening
  port on loopback.
- The wire between two sidecars is mTLS on the application's normal port
  (8080, 9090, whatever the service exposes).

For Linkerd:

- Outbound from the app goes to `127.0.0.1:4140`.
- Inbound to the pod goes to `127.0.0.1:4143`.
- Same mTLS-on-the-wire story.

So three distinct things are happening on three distinct paths, and only
one of them (the wire) is encrypted. The other two — app to sidecar, and
sidecar back to app — are plaintext on loopback. That's the leverage.
You can watch what the application told the sidecar to do, even when the
wire traffic is opaque.

```python
>>> conf.ifaces
```

In a meshed pod you should see `lo` and `eth0`. `lo` is where the
app-to-sidecar conversation lives.

## 2. Watching what the sidecar is doing

Sniff loopback for traffic to and from the sidecar's intercept ports.
This is the single most useful capture in mesh debugging because it
distinguishes three failure shapes that all look identical from outside:

- The app never made the call (no SYN to 15001).
- The app called and the sidecar dropped it (SYN to 15001, RST or no
  SYN/ACK back).
- The sidecar accepted but couldn't reach the upstream (SYN/ACK to the
  app, then a `503` response from the sidecar a moment later).

```python
>>> sniff(iface="lo", filter="tcp port 15001 or tcp port 15006",
...       prn=lambda p: print(p.summary()), store=False, count=50)
```

Watch the flag pattern. A healthy outbound call looks like:

```
app:34522 -> 127.0.0.1:15001  S
127.0.0.1:15001 -> app:34522  SA
app:34522 -> 127.0.0.1:15001  A
... data ...
```

An unhealthy one shows the app's SYN with no SYN/ACK in reply, or a
SYN/ACK followed quickly by FIN/RST from the sidecar. The latter is
usually a missing `ServiceEntry`, a `Sidecar` resource that scoped the
sidecar too tightly, or an authorization policy rejecting the outbound.

As a script:

```python
>>> !python3 /app/scripts/mesh/sidecar_traffic.py lo 30
>>> !python3 /app/scripts/mesh/sidecar_traffic.py lo 30 4140,4143
```

The summary at the end of the capture is the diagnostic. "12 SYNs sent,
0 SYN/ACKs back" is a silent drop. "12 SYNs sent, 12 SYN/ACKs, 11 RSTs"
is the sidecar accepting and then rejecting — look at the upstream side
next.

## 3. mTLS handshake between sidecars

The wire between two sidecars is TLS. The interesting question on a
mesh handshake isn't usually "did the cert validate" — it's "which
workload identity did the peer present". In SPIFFE-based meshes (Istio,
Linkerd) the identity is a URI in the certificate's
SubjectAlternativeName, like:

```
spiffe://cluster.local/ns/payments/sa/checkout
```

The existing TLS handshake script already covers the standard fields
(SNI, version, cipher, cert subject, validity):

```python
>>> !python3 /app/scripts/sniffing/tls_handshake.py eth0
```

For the SPIFFE URI specifically — which is the thing you actually want
when debugging "which workload was on the other end of this connection"
— use the SPIFFE script. It pulls the URI out of the SAN extension:

```python
>>> !python3 /app/scripts/mesh/spiffe_id.py eth0
```

Output:

```
10.0.0.5 -> spiffe://cluster.local/ns/payments/sa/checkout
10.0.0.6 -> spiffe://cluster.local/ns/payments/sa/ledger
10.0.0.7 -> (no SPIFFE identity)
```

The third line is just as useful as the first two. A peer with no
SPIFFE identity is either not in the mesh at all, or the connection
isn't going through a sidecar — which is exactly what you want to know
when you suspect traffic is bypassing the mesh.

A note on cert lifetime: Istio's default workload cert is 24 hours,
Linkerd's is 24 hours by default and often shorter. If you see
`certificate_expired` in the TLS handshake script the morning after a
control-plane outage, this is why. Watch the `not valid after` field —
if it's hours away rather than months, that's a mesh cert.

## 4. Common failure modes

The Envoy access log writes a two-letter response flag next to every
503. The flags tell you where in the proxy the failure was. The ones
you'll see repeatedly:

- **`NR` — no route.** The destination has no matching route in the
  sidecar's config. Service has no endpoints, or the `VirtualService` /
  `DestinationRule` doesn't match. On the wire: no outbound connection
  ever attempted. `sidecar_traffic.py` will show the SYN to 15001 and
  an immediate FIN from the sidecar back to the app.

- **`UF` — upstream failure.** Sidecar tried to connect to the upstream
  and failed. mTLS handshake error, DNS failure, network unreachable,
  TCP RST from the remote. On the wire: outbound SYN on eth0, then
  either no SYN/ACK or a TLS alert. Run `tls_handshake.py` on eth0 to
  see the alert description.

- **`UH` — no healthy upstream.** Endpoints exist but the sidecar's
  health checks have marked them all unhealthy. No connection attempt
  on the wire. Look at the upstream pod's readiness probe.

- **Identity mismatch.** Wrong SPIFFE URI on either side. The handshake
  completes (no TLS alert) but Envoy rejects the request at the RBAC
  layer with a 403. Common after a namespace rename, a workload
  restart that picked up a stale cert from a cached secret, or an
  `AuthorizationPolicy` referencing the old identity. `spiffe_id.py`
  is the fastest way to confirm which identity the peer presented.

- **PERMISSIVE vs STRICT mTLS.** In `PERMISSIVE` mode the sidecar
  accepts both plaintext and mTLS on the inbound port. On the wire you
  may see flows with no ClientHello at all — the client wrote HTTP
  directly and the sidecar accepted it. In `STRICT` mode a plaintext
  client gets a TCP RST after the SYN/ACK. If you're migrating from
  permissive to strict and seeing 503s, run `tls_sni.py` and look for
  flows on the service port with no SNI — those are the plaintext
  callers you're about to break.

## 5. Did the request even reach the sidecar?

If a single pod is bypassing the mesh, the iptables redirect chain is
the first thing to check. The Istio init container installs rules in
the `nat` table that redirect everything to 15001/15006. If those rules
are missing — wrong init container, CNI conflict, `restartPolicy`
weirdness after a node reboot — traffic flows past the sidecar entirely.

From the shell:

```python
>>> !iptables -t nat -L PREROUTING -n
>>> !iptables -t nat -L OUTPUT -n
```

You should see jumps to `ISTIO_INBOUND` and `ISTIO_OUTPUT`. If you
don't, the sidecar isn't intercepting.

The Scapy confirmation is simpler: sniff for traffic going to the
*original* destination port from inside the pod's network namespace. If
the redirect is working, the app's writes never appear on eth0 with the
original port as the destination — they get rewritten to 15001 on
loopback first. If the redirect is broken, you'll see the raw
destination port on eth0:

```python
>>> sniff(iface="eth0",
...       filter="tcp port 8080 and tcp[tcpflags] & tcp-syn != 0",
...       prn=lambda p: print(p[IP].src, "->", p[IP].dst, p[TCP].dport),
...       store=False, count=20)
```

If you see SYNs to port 8080 leaving on eth0 from the application's
source port (not from the sidecar's), the redirect chain is broken and
the mesh isn't doing anything for this pod. That's a CNI or
init-container problem, not a mesh-config problem.

## 6. Egress through the mesh

Outbound traffic to external hosts is where mesh configuration gets
subtle. The sidecar can be configured to:

- Pass the traffic through opaquely (TCP proxy).
- Originate TLS itself (app speaks HTTP, sidecar speaks HTTPS to the
  external host).
- Block the traffic entirely (no `ServiceEntry`, with
  `REGISTRY_ONLY` outbound policy).

To confirm which is happening, watch loopback and eth0 simultaneously.
If the sidecar is originating TLS, the app-to-sidecar leg on loopback
will be plaintext HTTP, and the sidecar-to-external leg on eth0 will
have a TLS ClientHello with the external host's SNI.

```python
>>> # Terminal 1
>>> sniff(iface="lo", filter="tcp port 15001",
...       lfilter=lambda p: TCP in p and Raw in p,
...       prn=lambda p: print("lo:", bytes(p[Raw])[:80]),
...       store=False)
```

```python
>>> # Terminal 2 (or another Scapy session)
>>> load_layer("tls")
>>> sniff(iface="eth0", filter="tcp port 443",
...       lfilter=lambda p: p.haslayer(TLSClientHello),
...       prn=lambda p: print("eth0 SNI:",
...                           p[TLSClientHello].ext[0].servernames[0].servername.decode()),
...       store=False)
```

If you see `GET / HTTP/1.1\r\nHost: api.example.com` on loopback and a
ClientHello with SNI `api.example.com` on eth0 a millisecond later, the
sidecar is originating TLS. That's `ServiceEntry` with
`resolution: DNS` and `tls.mode: SIMPLE` working as intended.

If you see plaintext on both sides, the sidecar is TCP-proxying without
originating TLS — the app is speaking HTTPS itself and the sidecar
isn't doing anything useful for this flow. Fine if intentional,
surprising if not.

If you see plaintext on loopback and nothing on eth0, the sidecar is
blocking the egress. Check the global `outboundTrafficPolicy.mode` and
whether a `ServiceEntry` exists for the host.
