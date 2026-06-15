#!/usr/bin/env python3
"""Correlate TLS ClientHello + ServerHello + Certificate + Alert into a
per-handshake report. Answers "mTLS broke", "cert rotation broke us",
"why is the mesh rejecting us silently" without terminating TLS.

Usage:  python3 /app/scripts/sniffing/tls_handshake.py eth0
        python3 /app/scripts/sniffing/tls_handshake.py eth0 200
"""
import sys
from scapy.all import sniff, load_layer, IP, TCP

iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0

load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate
from scapy.layers.tls.record import TLSAlert

from cryptography import x509
from cryptography.hazmat.backends import default_backend

TLS_VERSIONS = {
    0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}

ALERT_LEVELS = {1: "warning", 2: "fatal"}
ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 60: "export_restriction", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}

flows = {}


def flow_key(p):
    return (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)


def reverse_key(k):
    return (k[2], k[3], k[0], k[1])


def cipher_name(num):
    try:
        from scapy.layers.tls.crypto.suites import _tls_cipher_suites
        return _tls_cipher_suites.get(num, f"0x{num:04x}")
    except Exception:
        return f"0x{num:04x}"


def alpn_list(ext):
    out = []
    for proto in getattr(ext, "protocols", []) or []:
        name = getattr(proto, "protocol", b"")
        if isinstance(name, bytes):
            out.append(name.decode(errors="replace"))
        else:
            out.append(str(name))
    return out


def parse_client_hello(ch):
    info = {"sni": None, "alpn_offered": [], "ciphers": []}
    for c in getattr(ch, "ciphers", []) or []:
        info["ciphers"].append(cipher_name(c))
    for ext in ch.ext or []:
        t = getattr(ext, "type", None)
        if t == 0 and getattr(ext, "servernames", None):
            info["sni"] = ext.servernames[0].servername.decode(errors="replace")
        elif t == 16:
            info["alpn_offered"] = alpn_list(ext)
    return info


def parse_server_hello(sh):
    info = {"version": None, "cipher": None, "alpn_selected": None}
    ver = getattr(sh, "version", None)
    for ext in sh.ext or []:
        t = getattr(ext, "type", None)
        if t == 43:
            sv = getattr(ext, "version", None)
            if sv is not None:
                ver = sv
        elif t == 16:
            picks = alpn_list(ext)
            if picks:
                info["alpn_selected"] = picks[0]
    if ver is not None:
        info["version"] = TLS_VERSIONS.get(ver, f"0x{ver:04x}")
    c = getattr(sh, "cipher", None)
    if c is not None:
        info["cipher"] = cipher_name(c)
    return info


def parse_certificate(cert_msg):
    der = None
    certs = getattr(cert_msg, "certs", None) or []
    if not certs:
        return None
    first = certs[0]
    raw = first[1] if isinstance(first, tuple) and len(first) >= 2 else first
    if hasattr(raw, "x509Cert"):
        try:
            der = bytes(raw.x509Cert)
        except Exception:
            der = None
    if der is None:
        try:
            der = bytes(raw)
        except Exception:
            return None
    try:
        c = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return None
    sans = []
    try:
        ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    try:
        nb = c.not_valid_before_utc
        na = c.not_valid_after_utc
    except AttributeError:
        nb = c.not_valid_before
        na = c.not_valid_after
    return {
        "subject": c.subject.rfc4514_string(),
        "issuer": c.issuer.rfc4514_string(),
        "not_before": nb.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": na.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "sans": sans,
    }


def emit(key, data):
    src, sport, dst, dport = key
    print(f"[{src}:{sport} -> {dst}:{dport}]")
    if data.get("sni"):
        print(f"  SNI:           {data['sni']}")
    if data.get("alpn_offered"):
        print(f"  ALPN offered:  {', '.join(data['alpn_offered'])}")
    if data.get("ciphers"):
        print(f"  ciphers:       {', '.join(data['ciphers'])}")
    if data.get("version"):
        print(f"  TLS version:   {data['version']}")
    if data.get("alpn_selected"):
        print(f"  ALPN selected: {data['alpn_selected']}")
    if data.get("cipher"):
        print(f"  cipher chosen: {data['cipher']}")
    cert = data.get("cert")
    if cert:
        print(f"  cert subject:  {cert['subject']}")
        print(f"  cert issuer:   {cert['issuer']}")
        print(f"  not valid before: {cert['not_before']}")
        print(f"  not valid after:  {cert['not_after']}")
        if cert["sans"]:
            print(f"  SANs:          {', '.join(cert['sans'])}")
    print()


def maybe_emit(key):
    data = flows.get(key)
    if not data:
        return
    if not (data.get("_client") and data.get("_server")):
        return
    if data.get("version") == "TLSv1.3" or data.get("_cert_seen"):
        emit(key, data)
        flows.pop(key, None)


def handle(p):
    if not (p.haslayer(IP) and p.haslayer(TCP)):
        return

    if p.haslayer(TLSAlert):
        alert = p[TLSAlert]
        lvl = ALERT_LEVELS.get(getattr(alert, "level", None), str(getattr(alert, "level", "?")))
        desc = ALERT_DESCRIPTIONS.get(getattr(alert, "descr", None), str(getattr(alert, "descr", "?")))
        src, sport, dst, dport = flow_key(p)
        print(f"[{src}:{sport} -> {dst}:{dport}] ALERT level={lvl} description={desc}")
        flows.pop(flow_key(p), None)
        flows.pop(reverse_key(flow_key(p)), None)
        return

    if p.haslayer(TLSClientHello):
        k = flow_key(p)
        slot = flows.setdefault(k, {})
        slot.update(parse_client_hello(p[TLSClientHello]))
        slot["_client"] = True

    if p.haslayer(TLSServerHello):
        ck = reverse_key(flow_key(p))
        slot = flows.setdefault(ck, {})
        slot.update(parse_server_hello(p[TLSServerHello]))
        slot["_server"] = True
        maybe_emit(ck)

    if p.haslayer(TLSCertificate):
        ck = reverse_key(flow_key(p))
        slot = flows.setdefault(ck, {})
        cert = parse_certificate(p[TLSCertificate])
        if cert:
            slot["cert"] = cert
        slot["_cert_seen"] = True
        maybe_emit(ck)


sniff(iface=iface, filter="tcp port 443",
      prn=handle, store=False, count=count)
