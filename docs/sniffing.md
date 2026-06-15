# Packet capture

This guide is about getting bytes off the wire and doing something with
them — decoding protocols, watching what an application is actually doing,
saving traffic for later analysis, and digging into TLS without breaking
it.

`tcpdump` is faster to type when all you want is to see bytes scroll
past. Scapy earns its keep when you want to *act* on the bytes: filter on
protocol semantics, correlate flows, decode application layers, or
generate a reply. Most of this guide is about that second category.

Every example assumes you're at the Scapy prompt inside the ttyd
terminal — `python -m scapy.__init__` from the shell. The IPython shell
escape `!cmd` runs `cmd` in sh without leaving the Scapy session.

## Watching traffic go past

The simplest possible capture is one line:

```python
>>> sniff(iface="eth0", count=20).summary()
```

`sniff()` returns a `PacketList` you can slice, filter, and feed into
anything else. The `.summary()` call prints one line per packet. If you
want full decode of each packet, swap it for `.show()`:

```python
>>> sniff(iface="eth0", count=5).show()
```

For "follow what's happening on this interface and don't store anything",
the pattern is `prn=` with `store=False`. The `prn=` callable runs on
each packet as it arrives:

```python
>>> sniff(iface="eth0", prn=lambda p: print(p.summary()),
...       store=False, count=0)
```

`store=False` keeps memory flat — important on a busy interface. `count=0`
runs until you Ctrl-C.

As a script:

```python
>>> !python3 /app/scripts/sniffing/live_summary.py eth0
>>> !python3 /app/scripts/sniffing/live_summary.py eth0 'tcp port 443'
```

## Two kinds of filter

Scapy gives you two ways to select packets, with very different cost
profiles.

The first is the BPF filter, passed as `filter=`. BPF is compiled and
runs in the kernel, so the userspace process only ever sees the matching
packets. This is what you should use whenever possible.

```python
>>> sniff(iface="eth0", filter="tcp port 443 and host 10.0.0.5", count=50)
```

The second is `lfilter=`, a Python callable that runs once per packet in
userspace. Slow, but it has access to Scapy's full dissection — you can
filter on fields BPF doesn't know about.

```python
>>> sniff(iface="eth0",
...       lfilter=lambda p: TCP in p and p[TCP].dport == 443 and len(p) > 1400)
```

The rule of thumb: anything that's expressible in BPF goes in `filter=`.
Use `lfilter=` only for things BPF can't see — protocol-layer presence,
decoded field values, packet length tests beyond simple offsets.

BPF syntax that covers most of what you'll write:

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

## Saving to pcap

Long captures shouldn't live in RAM. The `PcapWriter` streams packets to
disk as they come in:

```python
>>> w = PcapWriter("/tmp/long.pcap", append=True, sync=True)
>>> sniff(iface="eth0", prn=w.write, store=False, count=0)
```

`sync=True` flushes after each packet. That costs you a little
performance but means if the container is killed mid-capture, the file
on disk is still a valid pcap.

To copy the file out to your local machine, run from a host shell (not
inside ttyd):

```sh
docker cp <container>:/tmp/long.pcap .
kubectl -n scapy cp <pod>:/tmp/long.pcap ./long.pcap
```

As a script:

```python
>>> !python3 /app/scripts/sniffing/to_pcap.py eth0 'port 443' /tmp/tls.pcap
```

## Reading a pcap back

For small files, `rdpcap` loads the whole thing into memory:

```python
>>> pkts = rdpcap("/tmp/tls.pcap")
>>> pkts.filter(lambda p: TCP in p and p[TCP].flags & 0x02).summary()
```

For big files, use the streaming reader. It walks the file one packet at
a time, which lets you grep multi-gigabyte captures without running out
of RAM:

```python
>>> with PcapReader("/tmp/huge.pcap") as pr:
...     for p in pr:
...         if DNS in p and p[DNS].qr == 0:
...             print(p[DNSQR].qname.decode())
```

The extract-DNS-from-pcap idiom is also packaged as a script:

```python
>>> !python3 /app/scripts/sniffing/pcap_dns.py /tmp/huge.pcap
```

## Looking at HTTP

Plaintext HTTP requests are easy. Load the HTTP layer and watch for the
request object:

```python
>>> load_layer("http")
>>> sniff(iface="eth0", filter="tcp port 80",
...       lfilter=lambda p: p.haslayer("HTTPRequest"),
...       prn=lambda p: print(p["HTTPRequest"].Method.decode(),
...                           p["HTTPRequest"].Host.decode() +
...                           p["HTTPRequest"].Path.decode()),
...       count=50)
```

```python
>>> !python3 /app/scripts/sniffing/http_requests.py eth0
```

HTTPS is more interesting because the cleartext is mostly gone. The
useful exception is the TLS ClientHello — the SNI extension is in plain
view, and it's almost always the answer when someone asks "which
external hosts is this pod calling".

```python
>>> load_layer("tls")
>>> def sni(p):
...     if p.haslayer(TLSClientHello):
...         for ext in p[TLSClientHello].ext or []:
...             if ext.type == 0:
...                 print(p[IP].dst, "->",
...                       ext.servernames[0].servername.decode())
>>> sniff(iface="eth0", filter="tcp port 443", prn=sni, count=200)
```

```python
>>> !python3 /app/scripts/sniffing/tls_sni.py eth0
```

## When SNI isn't enough: full TLS handshake

If you're chasing an mTLS failure, a cert rotation that broke
service-to-service traffic, or "the mesh is silently rejecting us", you
need more than the SNI. The handshake script correlates ClientHello,
ServerHello, the server's certificate, and any handshake alerts into one
report per flow:

```python
>>> !python3 /app/scripts/sniffing/tls_handshake.py eth0
```

A successful handshake renders as:

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

A failure renders as a single line:

```
[10.0.0.5:51234 -> 1.2.3.4:443] ALERT level=fatal description=unknown_ca
```

The alert description tells you most of what you need. `unknown_ca`,
`bad_certificate`, `certificate_expired`, `unsupported_certificate`,
`handshake_failure`, and `protocol_version` together cover the majority
of trust-store and cert-rotation incidents.

A note on TLS 1.3: the server certificate is sent inside encrypted
handshake records, so the script can't print cert fields for TLS 1.3
flows. SNI, ALPN, version, and chosen cipher all still come through.

## Finding the DNS lookups behind an application

```python
>>> def show(p):
...     if p.haslayer(DNS) and p[DNS].qr == 0:
...         print(p[IP].src, "->", p[DNSQR].qname.decode().rstrip("."))
>>> sniff(iface="any", filter="udp port 53", prn=show, store=False)
```

`iface="any"` is Linux-only and is exactly the right thing inside a
container or pod. On macOS use the actual interface name.

## Plotting

The image already has matplotlib, PyX, TeX Live, and Ghostscript, so any
of Scapy's `plot()` / `pdfdump()` / `world_trace()` helpers work
out-of-the-box. Quick packet-size histogram:

```python
>>> import matplotlib
>>> matplotlib.use("Agg")
>>> import matplotlib.pyplot as plt
>>> pkts = sniff(iface="eth0", count=2000, timeout=30)
>>> pkts.plot(lambda p: len(p))
>>> plt.gcf().savefig("/tmp/sizes.png")
```

There's a subtle gotcha here: `PacketList.plot()` returns a list of
`Line2D` objects, not a `Figure`. You can't chain `.savefig()` off it
directly. `plt.gcf()` grabs the current figure that `.plot()` drew into.

```python
>>> !python3 /app/scripts/sniffing/plot_sizes.py eth0 2000 /tmp/sizes.png
```

## Per-flow TCP health

When the dashboards say everything is fine but the API is slow,
retransmits and zero-window events are usually the first place to look.
The `tcp_health` script captures TCP for a window, then prints one row
per flow with retransmits, out-of-order arrivals, zero-window
advertisements, and the handshake RTT:

```python
>>> !python3 /app/scripts/sniffing/tcp_health.py eth0
>>> !python3 /app/scripts/sniffing/tcp_health.py eth0 'host 10.0.0.5' 60
```

Output:

```
                       flow  pkts  retx  ooo  zwin   rtt_ms
       10.0.0.5:51234 ->  1.2.3.4:443    142    11    3     0   42.3
       10.0.0.5:51235 ->  1.2.3.4:443     98     0    0     0   12.1
       10.0.0.5:51236 ->  10.0.0.6:5432   54     0    0     2    1.4
```

What each column means:

- `retx` counts duplicated `(seq, payload_len)` in the same direction.
  Anything above 1–2% of `pkts` is worth investigating.
- `ooo` is the count of packets that arrived with a sequence number
  below what was already seen. A few is normal; many means reordering
  on the path.
- `zwin` is TCP zero-window advertisements. Receiver is overwhelmed —
  often a sign of a slow consumer, not a slow network.
- `rtt_ms` is the handshake RTT (SYN to SYN/ACK). It prints `-` if you
  started sniffing mid-flow. If you want RTT, start the sniffer first,
  then trigger the request.

## Reassembling a TCP stream

For plaintext protocols where you just want to read what was said,
`PacketList.sessions()` groups packets by 4-tuple:

```python
>>> pkts = sniff(iface="eth0", filter="tcp port 80", count=500)
>>> for key, stream in pkts.sessions().items():
...     payload = b"".join(bytes(p[TCP].payload) for p in stream
...                        if TCP in p and Raw in p)
...     if payload:
...         print(key)
...         print(payload[:200])
...         print("-" * 60)
```

This isn't real TCP reassembly: it doesn't reorder by sequence number,
doesn't handle retransmits, and doesn't track FIN. For anything that
matters, save a pcap and open it in Wireshark — "Follow TCP Stream" is
what you want.

```python
>>> !python3 /app/scripts/sniffing/tcp_sessions.py eth0 80 500
```
