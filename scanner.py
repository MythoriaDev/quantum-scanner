"""
Quantum-Readiness Scanner - core scanning logic.

Checks a public website's HTTPS (TLS) setup for quantum-safety:
  1. Does it support post-quantum hybrid key exchange (X25519MLKEM768)?
     This protects traffic from "harvest now, decrypt later" attacks.
  2. Which TLS version and cipher does it use?
  3. What certificate does it use (key type, size, expiry, trust)?

Uses only the Python standard library plus the cryptography package.
"""

import ipaddress
import os
import re
import socket
import ssl
import struct
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

PQ_GROUP_ID = 0x11EC  # X25519MLKEM768 (IANA codepoint), used by Chrome, Firefox, Cloudflare, Google...
PQ_GROUP_NAME = "X25519MLKEM768"

# Special ServerHello.random value that marks a HelloRetryRequest (RFC 8446 4.1.3)
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

ALERTS = {
    40: "handshake_failure",
    47: "illegal_parameter",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    112: "unrecognized_name",
}

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #
def normalize_target(raw):
    """Turn 'https://www.example.com/path' or 'example.com:8443' into (host, port)."""
    s = (raw or "").strip()
    if not s:
        raise ScanError("Please enter a website address.")
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)  # drop scheme
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s.split("@")[-1]  # drop any user:pass@
    port = 443
    if s.startswith("["):  # [IPv6]:port
        end = s.find("]")
        if end == -1:
            raise ScanError("Invalid address.")
        host = s[1:end]
        rest = s[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif s.count(":") == 1:
        host, p = s.split(":")
        if not p.isdigit():
            raise ScanError("Invalid port number.")
        port = int(p)
    else:
        host = s
    host = host.strip().rstrip(".").lower()
    if not (1 <= port <= 65535):
        raise ScanError("Invalid port number.")
    if not host:
        raise ScanError("Please enter a website address.")
    if not _is_ip(host) and not HOST_RE.match(host):
        raise ScanError("That doesn't look like a valid website address: %s" % raw)
    return host, port


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve(host, port, allow_private):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError("Could not find '%s' (DNS lookup failed). Check the spelling." % host)
    if not infos:
        raise ScanError("Could not find '%s'." % host)
    if not allow_private:
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                raise ScanError("'%s' points to a private/internal address; only public websites can be scanned." % host)
    return infos[0][4][0]


# --------------------------------------------------------------------------- #
# Post-quantum probe (raw TLS 1.3 ClientHello offering ONLY X25519MLKEM768)
# --------------------------------------------------------------------------- #
def _ext(ext_type, data):
    return struct.pack("!HH", ext_type, len(data)) + data


def _build_pq_client_hello(host):
    # Key share for X25519MLKEM768 = ML-KEM-768 encapsulation key (1184 bytes) || X25519 key (32 bytes).
    # The ML-KEM key is a structurally valid key (all-zero polynomial vector + random seed);
    # the X25519 key is the curve's base point. The handshake is never completed, so no
    # secret keys are needed - we only want to see which group the server picks.
    mlkem_ek = b"\x00" * 1152 + os.urandom(32)
    x25519_pub = b"\x09" + b"\x00" * 31
    key_share = mlkem_ek + x25519_pub

    exts = b""
    if not _is_ip(host):
        name = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("ascii")
        sni = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0x0000, struct.pack("!H", len(sni)) + sni)
    exts += _ext(0x000A, struct.pack("!HH", 2, PQ_GROUP_ID))  # supported_groups
    sig_algs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601, 0x0807, 0x0808]
    sa = b"".join(struct.pack("!H", a) for a in sig_algs)
    exts += _ext(0x000D, struct.pack("!H", len(sa)) + sa)  # signature_algorithms
    alpn_list = b"\x08http/1.1"
    exts += _ext(0x0010, struct.pack("!H", len(alpn_list)) + alpn_list)  # ALPN
    exts += _ext(0x002B, b"\x02\x03\x04")  # supported_versions: TLS 1.3 only
    exts += _ext(0x002D, b"\x01\x01")  # psk_key_exchange_modes
    ks_entry = struct.pack("!HH", PQ_GROUP_ID, len(key_share)) + key_share
    exts += _ext(0x0033, struct.pack("!H", len(ks_entry)) + ks_entry)  # key_share

    body = b"\x03\x03" + os.urandom(32)
    body += b"\x20" + os.urandom(32)  # legacy session id
    suites = b"\x13\x01\x13\x02\x13\x03"
    body += struct.pack("!H", len(suites)) + suites
    body += b"\x01\x00"  # compression: null
    body += struct.pack("!H", len(exts)) + exts

    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def _parse_server_hello(msg):
    """msg = ServerHello body. Returns dict(version, group, hrr)."""
    p = 0
    p += 2  # legacy_version
    random = msg[p:p + 32]; p += 32
    sid_len = msg[p]; p += 1 + sid_len
    p += 2  # cipher suite
    p += 1  # compression
    result = {"hrr": random == HRR_RANDOM, "version": 0x0303, "group": None}
    if p + 2 > len(msg):
        return result
    ext_total = struct.unpack("!H", msg[p:p + 2])[0]; p += 2
    end = min(len(msg), p + ext_total)
    while p + 4 <= end:
        etype, elen = struct.unpack("!HH", msg[p:p + 4]); p += 4
        edata = msg[p:p + elen]; p += elen
        if etype == 0x002B and len(edata) >= 2:
            result["version"] = struct.unpack("!H", edata[:2])[0]
        elif etype == 0x0033 and len(edata) >= 2:
            result["group"] = struct.unpack("!H", edata[:2])[0]
    return result


def probe_pq(host, port, ip, timeout=8.0):
    """Returns (supported: True/False/None, detail: str)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        return None, "Could not connect for post-quantum check (%s)." % e.__class__.__name__
    try:
        sock.settimeout(timeout)
        sock.sendall(_build_pq_client_hello(host))
        hs_buf = b""
        for _ in range(20):  # read up to 20 records
            header = _recv_exact(sock, 5)
            ctype, _ver, length = struct.unpack("!BHH", header)
            payload = _recv_exact(sock, length)
            if ctype == 0x15:  # alert
                desc = payload[1] if len(payload) > 1 else -1
                return False, "Server refused the post-quantum key exchange (TLS alert: %s)." % ALERTS.get(desc, desc)
            if ctype != 0x16:
                return None, "Unexpected response during post-quantum check."
            hs_buf += payload
            if len(hs_buf) >= 4:
                mtype = hs_buf[0]
                mlen = struct.unpack("!I", b"\x00" + hs_buf[1:4])[0]
                if len(hs_buf) >= 4 + mlen:
                    if mtype != 0x02:
                        return None, "Unexpected handshake message during post-quantum check."
                    sh = _parse_server_hello(hs_buf[4:4 + mlen])
                    if sh["version"] != 0x0304:
                        return False, "Server does not support TLS 1.3, which post-quantum key exchange requires."
                    if sh["group"] == PQ_GROUP_ID and not sh["hrr"]:
                        return True, "Server accepted %s hybrid post-quantum key exchange." % PQ_GROUP_NAME
                    if sh["hrr"]:
                        return False, "Server asked to fall back to a classical key exchange."
                    return False, "Server chose a classical key exchange."
        return None, "Response too long during post-quantum check."
    except EOFError:
        return False, "Server closed the connection when offered post-quantum key exchange."
    except (socket.timeout, TimeoutError):
        return None, "Timed out during post-quantum check."
    except OSError as e:
        return False, "Connection was reset when offered post-quantum key exchange (%s)." % e.__class__.__name__
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Standard TLS handshake + certificate inspection
# --------------------------------------------------------------------------- #
def _tls_connect(host, port, ip, timeout, verify, cafile):
    if verify:
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        # Python 3.13+ adds checks stricter than browsers; match browser behaviour instead.
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Python validates IP addresses against the certificate and skips SNI for IPs automatically.
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            return s.version(), s.cipher(), s.getpeercert(binary_form=True)


def _describe_key(cert):
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA (%s)" % key.curve.name, key.curve.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, 0


def _name_attr(name, oid):
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    except Exception:
        return ""


def inspect_tls(host, port, ip, timeout=8.0, cafile=None):
    info = {"cert_trusted": True, "cert_error": ""}
    try:
        version, cipher, der = _tls_connect(host, port, ip, timeout, True, cafile)
    except ssl.SSLCertVerificationError as e:
        info["cert_trusted"] = False
        info["cert_error"] = getattr(e, "verify_message", "") or str(e)
        try:
            version, cipher, der = _tls_connect(host, port, ip, timeout, False, None)
        except (ssl.SSLError, OSError) as e2:
            raise ScanError("HTTPS connection failed: %s" % e2)
    except ssl.SSLError as e:
        raise ScanError("HTTPS connection failed (%s). The site may not support modern TLS." % e.reason)
    except (socket.timeout, TimeoutError):
        raise ScanError("Connection timed out. Is the website online and using HTTPS on port %d?" % port)
    except ConnectionRefusedError:
        raise ScanError("Connection refused on port %d. The site may not offer HTTPS." % port)
    except OSError as e:
        raise ScanError("Could not connect: %s" % e)

    info["tls_version"] = version or "Unknown"
    info["cipher"] = cipher[0] if cipher else "Unknown"
    info["cipher_bits"] = cipher[2] if cipher else 0

    cert = x509.load_der_x509_certificate(der)
    key_type, key_bits = _describe_key(cert)
    try:
        expires = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    info.update({
        "cert_key_type": key_type,
        "cert_key_bits": key_bits,
        "cert_sig_alg": cert.signature_algorithm_oid._name,
        "cert_issuer": _name_attr(cert.issuer, x509.NameOID.ORGANIZATION_NAME)
        or _name_attr(cert.issuer, x509.NameOID.COMMON_NAME) or "Unknown",
        "cert_subject": _name_attr(cert.subject, x509.NameOID.COMMON_NAME) or host,
        "cert_expires": expires.strftime("%Y-%m-%d"),
        "cert_days_left": (expires - datetime.now(timezone.utc)).days,
    })
    return info


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _score(r):
    findings = []  # (status, title, explanation); status in good/warn/bad/info
    score = 0

    # 1. Post-quantum key exchange - 50 points
    if r["pq_supported"] is True:
        score += 50
        findings.append(("good", "Post-quantum key exchange: supported",
                         "Traffic is protected with hybrid %s encryption, so data intercepted today "
                         "cannot be decrypted later by a quantum computer." % PQ_GROUP_NAME))
    elif r["pq_supported"] is False:
        findings.append(("bad", "Post-quantum key exchange: NOT supported",
                         "Traffic uses only classical key exchange. Attackers can record it today and "
                         "decrypt it once quantum computers are powerful enough (\"harvest now, decrypt later\")."))
    else:
        findings.append(("warn", "Post-quantum key exchange: could not be determined", r["pq_detail"]))

    # 2. TLS version - 20 points
    v = r["tls_version"]
    if v == "TLSv1.3":
        score += 20
        findings.append(("good", "TLS 1.3 in use", "The latest version of the HTTPS protocol, required for post-quantum upgrades."))
    elif v == "TLSv1.2":
        score += 10
        findings.append(("warn", "TLS 1.2 in use (no TLS 1.3)",
                         "TLS 1.2 is still acceptable but cannot use post-quantum key exchange. Upgrading to TLS 1.3 is the first step."))
    else:
        findings.append(("bad", "Outdated TLS version: %s" % v, "This protocol version is insecure and should be disabled."))

    # 3. Symmetric cipher - 10 points
    bits = r["cipher_bits"] or 0
    if bits >= 256:
        score += 10
        findings.append(("good", "Strong encryption cipher (%d-bit)" % bits, "%s is considered quantum-resistant." % r["cipher"]))
    elif bits >= 128:
        score += 8
        findings.append(("info", "Encryption cipher: %d-bit" % bits,
                         "%s is currently considered adequate; 256-bit gives a larger safety margin against quantum attacks." % r["cipher"]))
    else:
        findings.append(("bad", "Weak encryption cipher (%d-bit)" % bits, "%s should be replaced." % r["cipher"]))

    # 4. Certificate hygiene - 20 points
    if r["cert_trusted"]:
        score += 10
        findings.append(("good", "Certificate is trusted", "Issued by %s." % r["cert_issuer"]))
    else:
        findings.append(("bad", "Certificate is NOT trusted", "Browsers will show a warning: %s" % r["cert_error"]))

    days = r["cert_days_left"]
    if days < 0:
        findings.append(("bad", "Certificate has expired", "Expired on %s." % r["cert_expires"]))
    elif days < 30:
        score += 2
        findings.append(("warn", "Certificate expires soon", "Expires on %s (%d days)." % (r["cert_expires"], days)))
    else:
        score += 5
        findings.append(("good", "Certificate is valid", "Expires on %s." % r["cert_expires"]))

    kt, kb = r["cert_key_type"], r["cert_key_bits"]
    strong = (kt == "RSA" and kb >= 2048) or kt.startswith("ECDSA") or kt in ("Ed25519", "Ed448")
    if strong:
        score += 5
    findings.append(("info" if strong else "bad",
                     "Certificate key: %s %d-bit (quantum-vulnerable)" % (kt, kb),
                     "All certificates on the public web today use classical signatures that a future quantum computer "
                     "could forge. This is expected: post-quantum certificates are not yet issued by public CAs, so "
                     "plan to adopt them when available." + ("" if strong else " This key is also too weak by today's standards.")))

    score = max(0, min(100, score))
    if not r["cert_trusted"] or days < 0:
        score = min(score, 50)  # a broken certificate caps the overall grade
    if v not in ("TLSv1.3", "TLSv1.2"):
        score = min(score, 30)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return score, grade, findings


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def scan(target, timeout=8.0, allow_private=False, cafile=None):
    """Scan one website. Always returns a dict; on failure dict['error'] is set."""
    result = {"target": str(target).strip(), "error": None,
              "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    try:
        host, port = normalize_target(target)
        result.update({"host": host, "port": port})
        ip = _resolve(host, port, allow_private)
        result["ip"] = ip
        result.update(inspect_tls(host, port, ip, timeout, cafile))
        pq, detail = probe_pq(host, port, ip, timeout)
        result["pq_supported"], result["pq_detail"] = pq, detail
        score, grade, findings = _score(result)
        result.update({"score": score, "grade": grade, "findings": findings})
    except ScanError as e:
        result["error"] = str(e)
    except Exception as e:  # never crash the app
        result["error"] = "Unexpected error: %s" % e
    return result


if __name__ == "__main__":
    import json
    import sys
    for t in sys.argv[1:] or ["cloudflare.com"]:
        print(json.dumps(scan(t), indent=2, default=str))
