# Packet capture

`tcpdump` is fine for "show me bytes on the wire". Use Scapy when you want
to **do** something with the bytes — decode by protocol, filter on
semantics, correlate, generate a reply.

Everything below assumes you're at the ttyd prompt at
**http://localhost:8080**.

## Live decode

One line per packet, prints until you Ctrl-C:

```sh
python3 /app/scripts/sniffing/live_summary.py eth0
python3 /app/scripts/sniffing/live_summary.py eth0 'tcp port 443'
```

Want full decode of each packet instead of a one-liner? Drop into `scapy`:

```python
sniff(iface="eth0", prn=lambda p: p.show(), count=10)
```

## Filters: BPF vs lfilter

Two filters, very different costs.

```python
# BPF — compiled, runs in kernel, cheap. Use this whenever possible.
sniff(iface="eth0", filter="tcp port 443 and host 10.0.0.5", count=50)

# lfilter — Python callback, runs per packet in userspace. Slow but flexible.
sniff(iface="eth0", lfilter=lambda p: TCP in p and p[TCP].dport == 443 and len(p) > 1400)
```

Rule of thumb: anything expressible in BPF goes in `filter=`. Use
`lfilter` only when you need Scapy-level knowledge.

BPF cheatsheet that covers 90% of what you'll type:

```
host 10.0.0.5
src host 10.0.0.5
dst port 443
tcp port 443
udp port 53
net 10.0.0.0/24
not arp and not stp
vlan 100 and tcp port 80
icmp[icmptype] = icmp-echoreply
```

## Save to pcap, open in Wireshark

Stream straight to disk so you don't OOM on a busy interface:

```sh
python3 /app/scripts/sniffing/to_pcap.py eth0 'port 443' /tmp/tls.pcap
```

`sync=True` is set on the writer — the file stays usable even if the
container gets killed.

Copy it out from your host shell:

```sh
docker cp <container>:/tmp/tls.pcap .
kubectl -n scapy cp <pod>:/tmp/tls.pcap ./tls.pcap
```

## Reading a pcap back

From `scapy`, small files:

```python
pkts = rdpcap("/tmp/tls.pcap")
pkts.filter(lambda p: TCP in p and p[TCP].flags & 0x02).summary()  # SYNs
```

For huge pcaps, use the streaming reader. Example: print every DNS
question from a multi-GB capture without loading it into RAM:

```sh
python3 /app/scripts/sniffing/pcap_dns.py /tmp/huge.pcap
```

## HTTP inspection

Plaintext HTTP — method, host, path:

```sh
python3 /app/scripts/sniffing/http_requests.py eth0
```

For HTTPS you only get the TLS handshake, but the SNI is in cleartext in
the ClientHello — which is what most "which hosts is this pod calling"
problems actually need:

```sh
python3 /app/scripts/sniffing/tls_sni.py eth0
```

## Full TLS handshake inspection

When SNI isn't enough — "mTLS broke after cert rotation", "the mesh is
rejecting us silently", "what cipher did they actually negotiate" — the
fuller inspector correlates ClientHello, ServerHello, the server's
certificate, and any handshake alerts into one report per flow:

```sh
python3 /app/scripts/sniffing/tls_handshake.py eth0
python3 /app/scripts/sniffing/tls_handshake.py eth0 200    # stop after 200 packets
```

Output per handshake:

```
[10.0.0.5:51234 -> 1.2.3.4:443]
  SNI:           example.com
  ALPN offered:  h2, http/1.1
  ciphers:       TLS_AES_128_GCM_SHA256, ...
  TLS version:   TLSv1.3
  ALPN selected: h2
  cipher chosen: TLS_AES_128_GCM_SHA256
  cert subject:  CN=example.com,O=Example Inc
  cert issuer:   CN=Let's Encrypt R3,O=Let's Encrypt
  not valid before: 2026-04-01 00:00:00 UTC
  not valid after:  2026-07-01 00:00:00 UTC
  SANs:          example.com, www.example.com
```

Alerts are flagged on their own line — that's the line you want to
copy-paste into the ticket:

```
[10.0.0.5:51234 -> 1.2.3.4:443] ALERT level=fatal description=unknown_ca
```

`unknown_ca`, `bad_certificate`, `certificate_expired`, `unsupported_certificate`,
`handshake_failure`, and `protocol_version` cover most of what you'll
see when an mTLS or trust-store change has broken a service-to-service
call.

## TCP health: retransmits, RTT, zero-windows

"The API is slow but the dashboard is green" — the single best Scapy
script for that problem. Captures TCP for a window, then prints a per-flow
table sorted worst-first by retransmit count:

```sh
python3 /app/scripts/sniffing/tcp_health.py eth0
python3 /app/scripts/sniffing/tcp_health.py eth0 'host 10.0.0.5' 60
```

Columns:

- `pkts` — packets in the flow.
- `retx` — retransmits (duplicate `(seq, len)` in the same direction).
  Anything above 1–2% of `pkts` is worth investigating.
- `ooo` — out-of-order arrivals (new seq lower than max seen so far).
  A few is normal; many means reordering on the path.
- `zwin` — TCP zero-window advertisements. Receiver is overwhelmed.
- `rtt_ms` — handshake RTT (SYN to SYN/ACK). Prints `-` if the sniff
  started mid-flow, so run the sniff before the slow request hits if you
  care about RTT.

## DNS who-asked-what

Drop into `scapy` and tail loopback or any interface for DNS queries:

```python
sniff(iface="any", filter="udp port 53",
      prn=lambda p: DNS in p and p[DNS].qr == 0
                  and print(p[IP].src, "->", p[DNSQR].qname.decode().rstrip(".")),
      store=False)
```

`iface="any"` is Linux-only. On macOS use the actual interface name.

## Plot something

Quick packet-size histogram, written to a PNG:

```sh
python3 /app/scripts/sniffing/plot_sizes.py eth0 2000 /tmp/sizes.png
```

Note: `PacketList.plot()` returns a list of `Line2D` objects, not a
Figure — the script uses `plt.gcf().savefig(...)` to grab the current
figure. Copy the PNG out the same way as a pcap.

## Reassembling a TCP stream

The `sessions()` helper bins packets by 4-tuple — it does **not** reorder
by sequence or handle retransmits, so it's only useful for plaintext
triage:

```sh
python3 /app/scripts/sniffing/tcp_sessions.py eth0 80 500
```

For anything serious, save a pcap and use Wireshark's "Follow TCP
Stream".
