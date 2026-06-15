#!/usr/bin/env python3
"""Extract SPIFFE identities from TLS handshakes on the wire. SPIFFE URIs
live in the cert's SubjectAlternativeName as URI entries — format
spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>. Flags peers
with no SPIFFE identity, which is what you want to spot mesh-bypassing
traffic.

Limitation: Scapy's sniff() doesn't reassemble TCP segments, so the
TLSCertificate handshake message is only visible when it fits in a single
TCP segment. That's typical for mesh-issued certs (small, single cert,
~1KB) but not for multi-KB public CA chains. If the end-of-capture summary
shows TLS records seen but zero certs parsed, the certs are
multi-segment — capture with tcpdump and analyse offline.

Usage:  python3 /app/scripts/mesh/spiffe_id.py
        python3 /app/scripts/mesh/spiffe_id.py eth0
        python3 /app/scripts/mesh/spiffe_id.py eth0 200
"""
import sys
from scapy.all import sniff, load_layer, IP, TCP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0

load_layer("tls")
from scapy.layers.tls.handshake import TLSCertificate
from scapy.layers.tls.record import TLS

from cryptography import x509
from cryptography.hazmat.backends import default_backend

reported = set()
stats = {"tls_records": 0, "certs_seen": 0, "spiffe_found": 0}


def cert_der(cert_msg):
    certs = getattr(cert_msg, "certs", None) or []
    if not certs:
        return None
    first = certs[0]
    raw = first[1] if isinstance(first, tuple) and len(first) >= 2 else first
    if hasattr(raw, "x509Cert"):
        try:
            return bytes(raw.x509Cert)
        except Exception:
            pass
    try:
        return bytes(raw)
    except Exception:
        return None


def spiffe_uris(der):
    try:
        c = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return []
    try:
        ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []
    try:
        uris = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    except Exception:
        return []
    return [u for u in uris if u.startswith("spiffe://")]


def handle(p):
    if not (p.haslayer(IP) and p.haslayer(TCP)):
        return
    if p.haslayer(TLS):
        stats["tls_records"] += 1
    if not p.haslayer(TLSCertificate):
        return
    stats["certs_seen"] += 1
    peer = p[IP].src
    flow = (peer, p[TCP].sport, p[IP].dst, p[TCP].dport)
    if flow in reported:
        return
    reported.add(flow)

    der = cert_der(p[TLSCertificate])
    if der is None:
        print(f"{peer} -> (no certificate parsed)")
        return
    uris = spiffe_uris(der)
    if not uris:
        print(f"{peer} -> (no SPIFFE identity)")
        return
    stats["spiffe_found"] += 1
    for u in uris:
        print(f"{peer} -> {u}")


print(f"watching TLS handshakes on {iface} for SPIFFE IDs "
      f"({'forever' if count == 0 else f'{count} packets'}) — Ctrl-C to stop")
try:
    sniff(iface=iface, filter="tcp", prn=handle, store=False, count=count)
except KeyboardInterrupt:
    pass

print()
print(f"summary: {stats['tls_records']} TLS records observed, "
      f"{stats['certs_seen']} Certificate messages parsed, "
      f"{stats['spiffe_found']} flows with SPIFFE identity")
if stats["tls_records"] > 0 and stats["certs_seen"] == 0:
    print("  hint: TLS traffic was seen but no Certificate message fit a single")
    print("        TCP segment. Capture with tcpdump and parse offline if you need")
    print("        identities from multi-segment cert chains.")
