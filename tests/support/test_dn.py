#!/usr/bin/env python3
"""tools/g5c-dn: DNS, HTTP, echo and RADIUS answer correctly over real sockets."""
import hashlib
import importlib.machinery
import importlib.util
import socket
import struct
import sys
import urllib.request
from pathlib import Path

path = str(Path(__file__).resolve().parent.parent.parent / "tools" / "g5c-dn")
loader = importlib.machinery.SourceFileLoader("g5c_dn", path)
spec = importlib.util.spec_from_loader("g5c_dn", loader)
dn = importlib.util.module_from_spec(spec)
loader.exec_module(dn)


def udp(port, data, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(data, ("127.0.0.1", port))
    try:
        return s.recvfrom(4096)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def dns_query(name, qtype=1):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + struct.pack("!HH", qtype, 1)


def radius_request(user, password, secret, ident=7):
    auth = bytes(range(16))
    pw = password.encode().ljust(16, b"\x00")
    pad = hashlib.md5(secret + auth).digest()
    enc = bytes(a ^ b for a, b in zip(pw, pad))
    attrs = bytes([1, 2 + len(user)]) + user.encode() + bytes([2, 18]) + enc
    return struct.pack("!BBH", 1, ident, 20 + len(attrs)) + auth + attrs, auth


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    secret = b"s3cret"
    srv = dn.Dn("127.0.0.1", dns=0, http_port=0, echo=0, radius=0, zone={"app.example": "198.51.100.7", "*": "192.0.2.9"}, users={"alice": "pw-alice"}, secret=secret).start()
    try:
        r = udp(srv.ports["dns"], dns_query("app.example"))
        check("DNS: a name in the zone", r is not None and r[:2] == b"\x12\x34" and r[3] & 0xF == 0 and r[-4:] == socket.inet_aton("198.51.100.7"), r)
        r = udp(srv.ports["dns"], dns_query("other.example"))
        check("DNS: the default answer", r is not None and r[-4:] == socket.inet_aton("192.0.2.9"), r)
        r = udp(srv.ports["dns"], dns_query("app.example", 28))
        check("DNS: AAAA gets an empty success", r is not None and r[3] & 0xF == 0 and struct.unpack("!H", r[6:8])[0] == 0, r)
        check("DNS: garbage is ignored, the service stays up", udp(srv.ports["dns"], b"\x00\x01", timeout=0.3) is None and udp(srv.ports["dns"], dns_query("app.example")) is not None)
        check("echo returns the datagram", udp(srv.ports["echo"], b"probe-123") == b"probe-123")
        base = "http://127.0.0.1:%d" % srv.ports["http"]
        check("HTTP: page", urllib.request.urlopen(base + "/", timeout=3).read() == b"g5c data network\n")
        check("HTTP: /bytes/N", len(urllib.request.urlopen(base + "/bytes/200000", timeout=5).read()) == 200000)
        try:
            urllib.request.urlopen(base + "/status/503", timeout=3)
            check("HTTP: /status/503", False)
        except urllib.error.HTTPError as e:
            check("HTTP: /status/503", e.code == 503)
        pkt, auth = radius_request("alice", "pw-alice", secret)
        r = udp(srv.ports["radius"], pkt)
        want = hashlib.md5(r[:4] + auth + r[20:] + secret).digest() if r else b""
        check("RADIUS: right password -> Access-Accept, authenticated with the secret", r is not None and r[0] == 2 and r[1] == 7 and r[4:20] == want, r)
        pkt, auth = radius_request("alice", "wrong", secret)
        r = udp(srv.ports["radius"], pkt)
        check("RADIUS: wrong password -> Access-Reject", r is not None and r[0] == 3, r)
        pkt, auth = radius_request("mallory", "x", secret)
        check("RADIUS: unknown user -> Access-Reject", udp(srv.ports["radius"], pkt)[0] == 3)
    finally:
        srv.stop()
    print("dn: PASS" if ok else "dn: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
