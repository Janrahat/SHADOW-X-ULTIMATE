"""A dependency-free DNS stub resolver (UDP with TCP fallback).

Termux frequently ships without dig/host/nslookup, so SHADOW-X speaks DNS
itself. Only standard library modules are used and every network call has a
hard timeout.
"""
from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

QTYPES: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}
TYPE_NAMES: Dict[int, str] = {value: key for key, value in QTYPES.items()}

RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


class DNSError(Exception):
    """Raised when no resolver could answer a query."""


def system_resolvers() -> List[str]:
    """Read /etc/resolv.conf, falling back to well-known public resolvers."""
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        candidate = parts[1].split("%")[0]
                        try:
                            ipaddress.ip_address(candidate)
                        except ValueError:
                            continue
                        if candidate not in servers:
                            servers.append(candidate)
    except OSError:
        pass
    if not servers:
        servers = list(DEFAULT_RESOLVERS)
    return servers


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire labels."""
    name = (name or "").strip().rstrip(".")
    out = bytearray()
    if name:
        for label in name.split("."):
            raw = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode("ascii", "replace")
            if not raw:
                continue
            if len(raw) > 63:
                raise DNSError("label too long: {!r}".format(label))
            out.append(len(raw))
            out.extend(raw)
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a possibly-compressed DNS name. Returns (name, next_offset)."""
    labels: List[str] = []
    jumped = False
    next_offset = offset
    seen = set()
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                raise DNSError("compression loop")
            seen.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length & 0xC0:
            raise DNSError("unsupported label type")
        offset += 1
        if offset + length > len(data):
            raise DNSError("truncated label")
        chunk = data[offset : offset + length]
        labels.append(chunk.decode("idna", "replace") if False else chunk.decode("ascii", "replace"))
        offset += length
    return (".".join(labels) + ("." if labels else "."), next_offset)


def build_query(name: str, rdtype: str = "A", qid: Optional[int] = None) -> Tuple[bytes, int]:
    """Build a single-question DNS packet."""
    rdtype = rdtype.upper()
    if rdtype not in QTYPES:
        raise DNSError("unsupported record type {} (supported: {})".format(rdtype, ", ".join(QTYPES)))
    identifier = qid if qid is not None else random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", QTYPES[rdtype], 1)
    return header + question, identifier


def _parse_records(data: bytes, offset: int, count: int) -> Tuple[List[Dict[str, Any]], int]:
    records: List[Dict[str, Any]] = []
    for _ in range(count):
        record_name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DNSError("truncated record header")
        rdtype, rdclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DNSError("truncated rdata")
        rdata = data[offset : offset + rdlength]
        value: Any = None
        type_name = TYPE_NAMES.get(rdtype, "TYPE{}".format(rdtype))
        try:
            if rdtype == 1 and rdlength == 4:
                value = socket.inet_ntoa(rdata)
            elif rdtype == 28 and rdlength == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rdtype in (2, 5, 12):
                value, _ = decode_name(data, offset)
            elif rdtype == 15:
                preference = struct.unpack("!H", rdata[:2])[0]
                exchange, _ = decode_name(data, offset + 2)
                value = {"preference": preference, "exchange": exchange}
            elif rdtype == 16:
                chunks: List[str] = []
                cursor = 0
                while cursor < rdlength:
                    size = rdata[cursor]
                    cursor += 1
                    chunks.append(rdata[cursor : cursor + size].decode("utf-8", "replace"))
                    cursor += size
                value = "".join(chunks)
            elif rdtype == 6:
                mname, cursor = decode_name(data, offset)
                rname, cursor = decode_name(data, cursor)
                serial, refresh, retry, expire, minimum = struct.unpack(
                    "!IIIII", data[cursor : cursor + 20]
                )
                value = {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
            elif rdtype == 33:
                priority, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = decode_name(data, offset + 6)
                value = {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                }
            elif rdtype == 257:
                flags = rdata[0] if rdata else 0
                tag_len = rdata[1] if len(rdata) > 1 else 0
                tag = rdata[2 : 2 + tag_len].decode("ascii", "replace")
                tag_value = rdata[2 + tag_len :].decode("utf-8", "replace")
                value = {"flags": flags, "tag": tag, "value": tag_value}
            else:
                value = rdata.hex()
        except Exception:
            value = rdata.hex()
        records.append(
            {
                "name": record_name,
                "type": type_name,
                "ttl": ttl,
                "class": rdclass,
                "value": value,
            }
        )
        offset += rdlength
    return records, offset


def parse_packet(data: bytes) -> Dict[str, Any]:
    """Parse a DNS response into a plain dictionary."""
    if len(data) < 12:
        raise DNSError("response shorter than a DNS header")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    offset = 12
    questions: List[Dict[str, Any]] = []
    for _ in range(qdcount):
        qname, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSError("truncated question")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append({"name": qname, "type": TYPE_NAMES.get(qtype, qtype), "class": qclass})
    answers, offset = _parse_records(data, offset, ancount)
    authority, offset = _parse_records(data, offset, nscount)
    additional, offset = _parse_records(data, offset, arcount)
    return {
        "id": qid,
        "rcode": rcode,
        "rcode_text": RCODES.get(rcode, "RCODE{}".format(rcode)),
        "truncated": bool(flags & 0x0200),
        "authenticated_data": bool(flags & 0x0020),
        "recursion_available": bool(flags & 0x0080),
        "questions": questions,
        "answers": answers,
        "authority": authority,
        "additional": additional,
    }


def _udp_exchange(packet: bytes, server: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        return data


def _tcp_exchange(packet: bytes, server: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length_raw = _recv_exact(sock, 2)
        length = struct.unpack("!H", length_raw)[0]
        return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise DNSError("connection closed while reading DNS response")
        buffer += chunk
    return buffer


def query(
    name: str,
    rdtype: str = "A",
    timeout: float = 5.0,
    servers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Resolve one record type, trying each resolver until one answers."""
    packet, identifier = build_query(name, rdtype)
    candidates = list(servers) if servers else system_resolvers()
    errors: List[str] = []
    for server in candidates:
        try:
            try:
                raw = _udp_exchange(packet, server, timeout)
            except socket.timeout:
                raise
            parsed = parse_packet(raw)
            if parsed.get("truncated"):
                raw = _tcp_exchange(packet, server, timeout)
                parsed = parse_packet(raw)
            if parsed.get("id") != identifier:
                raise DNSError("transaction id mismatch")
            parsed["server"] = server
            parsed["query"] = {"name": name, "type": rdtype.upper()}
            if parsed["rcode"] == 2:
                errors.append("{}: SERVFAIL".format(server))
                continue
            return parsed
        except (socket.timeout, OSError) as exc:
            errors.append("{}: {}".format(server, exc))
            continue
        except DNSError as exc:
            errors.append("{}: {}".format(server, exc))
            continue
    raise DNSError(
        "DNS query for {} {} failed ({})".format(name, rdtype.upper(), "; ".join(errors) or "no resolver")
    )


def get_records(name: str, rdtype: str = "A", timeout: float = 5.0) -> List[Any]:
    """Convenience wrapper returning just the answer values."""
    result = query(name, rdtype, timeout=timeout)
    return [answer["value"] for answer in result.get("answers", []) if answer.get("type") == rdtype.upper()]


def reverse_name(address: str) -> str:
    """Build the in-addr.arpa / ip6.arpa name for a PTR lookup."""
    ip = ipaddress.ip_address(str(address).strip().strip("[]"))
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    expanded = ip.exploded.replace(":", "")
    return ".".join(reversed(list(expanded))) + ".ip6.arpa"


def reverse_lookup(address: str, timeout: float = 5.0) -> List[str]:
    """PTR lookup, returning [] instead of raising when nothing is published."""
    try:
        result = query(reverse_name(address), "PTR", timeout=timeout)
    except DNSError:
        return []
    if result.get("rcode") == 3:
        return []
    return [item["value"] for item in result.get("answers", []) if item.get("type") == "PTR"]


def system_resolver_ok() -> bool:
    """Cheap self-test used by the dashboard and by tests."""
    try:
        query("example.com", "A", timeout=3.0)
        return True
    except Exception:
        return False
