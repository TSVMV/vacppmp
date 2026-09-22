"""Decode Ethernet / IP / transport / application layers from a packet payload."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

__all__ = ["Decoded", "decode_frame"]

ETHERTYPE = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
}

IP_PROTO = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}

WELL_KNOWN = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
}


@dataclass
class Decoded:
    """One decoded frame, with empty strings when a field is unknown."""

    link: str = ""
    ethertype: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: int = 0
    proto: str = ""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    dns_names: list[str] = field(default_factory=list)
    http_host: str = ""
    http_method: str = ""
    tls_sni: str = ""
    arp_spa: str = ""
    arp_tpa: str = ""


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _ipv6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def decode_frame(payload: bytes, linktype: int) -> Decoded:
    """Decode a single captured frame according to its pcap link type."""
    frame = Decoded(length=len(payload))
    if not payload:
        return frame
    if linktype == 1:
        return _ethernet(payload, frame)
    if linktype in (0, 108):
        return _null(payload, frame)
    if linktype in (12, 14, 228):
        return _ip(payload, frame)
    if linktype == 229:
        return _ipv6(payload, frame)
    if linktype == 113:
        return _sll(payload, frame)
    if linktype == 276:
        return _sll2(payload, frame)
    frame.link = f"dlt-{linktype}"
    return frame


def _ethernet(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 14:
        return frame
    frame.link = "ethernet"
    frame.dst_mac = _mac(payload[0:6])
    frame.src_mac = _mac(payload[6:12])
    ethertype = struct.unpack("!H", payload[12:14])[0]
    offset = 14
    if ethertype == 0x8100 and len(payload) >= 18:
        ethertype = struct.unpack("!H", payload[16:18])[0]
        offset = 18
    frame.ethertype = ETHERTYPE.get(ethertype, f"0x{ethertype:04x}")
    body = payload[offset:]
    if ethertype == 0x0800:
        return _ipv4_packet(body, frame)
    if ethertype == 0x86DD:
        return _ipv6(body, frame)
    if ethertype == 0x0806:
        return _arp(body, frame)
    return frame


def _null(payload: bytes, frame: Decoded) -> Decoded:
    frame.link = "null"
    if len(payload) < 4:
        return frame
    family = struct.unpack("<I", payload[:4])[0]
    if family in (2, 0x02000000):
        return _ipv4_packet(payload[4:], frame)
    if family in (24, 28, 30, 0x1C000000, 0x1E000000):
        return _ipv6(payload[4:], frame)
    return frame


def _sll(payload: bytes, frame: Decoded) -> Decoded:
    frame.link = "linux-sll"
    if len(payload) < 16:
        return frame
    proto = struct.unpack("!H", payload[14:16])[0]
    frame.ethertype = ETHERTYPE.get(proto, f"0x{proto:04x}")
    if proto == 0x0800:
        return _ipv4_packet(payload[16:], frame)
    if proto == 0x86DD:
        return _ipv6(payload[16:], frame)
    return frame


def _sll2(payload: bytes, frame: Decoded) -> Decoded:
    frame.link = "linux-sll2"
    if len(payload) < 20:
        return frame
    proto = struct.unpack("!H", payload[0:2])[0]
    frame.ethertype = ETHERTYPE.get(proto, f"0x{proto:04x}")
    if proto == 0x0800:
        return _ipv4_packet(payload[20:], frame)
    if proto == 0x86DD:
        return _ipv6(payload[20:], frame)
    return frame


def _ip(payload: bytes, frame: Decoded) -> Decoded:
    if not payload:
        return frame
    version = payload[0] >> 4
    if version == 4:
        return _ipv4_packet(payload, frame)
    if version == 6:
        return _ipv6(payload, frame)
    return frame


def _ipv4_packet(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 20:
        return frame
    version_ihl = payload[0]
    if version_ihl >> 4 != 4:
        return frame
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return frame
    proto = payload[9]
    frame.ip_version = 4
    frame.src_ip = _ipv4(payload[12:16])
    frame.dst_ip = _ipv4(payload[16:20])
    frame.proto = IP_PROTO.get(proto, f"ip-{proto}")
    body = payload[ihl:]
    if proto == 6:
        return _tcp(body, frame)
    if proto == 17:
        return _udp(body, frame)
    return frame


def _ipv6(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 40:
        return frame
    if payload[0] >> 4 != 6:
        return frame
    nxt = payload[6]
    frame.ip_version = 6
    frame.src_ip = _ipv6(payload[8:24])
    frame.dst_ip = _ipv6(payload[24:40])
    offset = 40
    for _ in range(8):
        if nxt in (0, 43, 44, 60) and len(payload) >= offset + 2:
            nxt = payload[offset]
            ext_len = (payload[offset + 1] + 1) * 8
            offset += ext_len
            continue
        break
    frame.proto = IP_PROTO.get(nxt, f"ip-{nxt}")
    body = payload[offset:]
    if nxt == 6:
        return _tcp(body, frame)
    if nxt == 17:
        return _udp(body, frame)
    return frame


def _arp(payload: bytes, frame: Decoded) -> Decoded:
    frame.proto = "ARP"
    if len(payload) < 28:
        return frame
    frame.arp_spa = _ipv4(payload[14:18])
    frame.arp_tpa = _ipv4(payload[24:28])
    frame.src_ip = frame.arp_spa
    frame.dst_ip = frame.arp_tpa
    return frame


def _tcp(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 20:
        return frame
    frame.src_port, frame.dst_port = struct.unpack("!HH", payload[0:4])
    offset = ((payload[12] >> 4) & 0x0F) * 4
    body = payload[offset:] if offset >= 20 else payload[20:]
    _app(frame, body)
    return frame


def _udp(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 8:
        return frame
    frame.src_port, frame.dst_port = struct.unpack("!HH", payload[0:4])
    _app(frame, payload[8:])
    return frame


def _app(frame: Decoded, body: bytes) -> None:
    ports = {frame.src_port, frame.dst_port}
    if 53 in ports:
        frame.dns_names = _dns_names(body)
        if frame.dns_names:
            frame.proto = "DNS"
            return
    if 80 in ports or 8080 in ports:
        host, method = _http(body)
        if host or method:
            frame.http_host = host
            frame.http_method = method
            frame.proto = "HTTP"
            return
    if 443 in ports:
        sni = _tls_sni(body)
        if sni:
            frame.tls_sni = sni
            frame.proto = "TLS"
            return
    service = WELL_KNOWN.get(frame.dst_port) or WELL_KNOWN.get(frame.src_port)
    if service and frame.proto in {"TCP", "UDP"}:
        frame.proto = service.upper() if service not in {"http", "https"} else frame.proto


def _dns_names(payload: bytes) -> list[str]:
    if len(payload) < 12:
        return []
    questions = struct.unpack("!H", payload[4:6])[0]
    if questions == 0 or questions > 64:
        return []
    offset = 12
    names: list[str] = []
    for _ in range(questions):
        name, offset = _dns_label(payload, offset)
        if offset + 4 > len(payload):
            break
        if name:
            names.append(name)
        offset += 4
    return names


def _dns_label(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    hops = 0
    jumped = False
    end = offset
    while offset < len(payload) and hops < 32:
        length = payload[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            continue
        offset += 1
        if offset + length > len(payload):
            break
        labels.append(_decode_label(payload[offset : offset + length]))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _decode_label(raw: bytes) -> str:
    try:
        return raw.decode("idna")
    except UnicodeError:
        return raw.decode("ascii", errors="replace")


def _http(payload: bytes) -> tuple[str, str]:
    if not payload:
        return "", ""
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return "", ""
    lines = text.split("\r\n")
    if not lines:
        return "", ""
    first = lines[0]
    method = ""
    if first.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")):
        method = first.split(" ", 1)[0]
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return host, method


def _tls_sni(payload: bytes) -> str:
    if len(payload) < 5 or payload[0] != 0x16:
        return ""
    if payload[1] != 0x03:
        return ""
    record_len = struct.unpack("!H", payload[3:5])[0]
    body = payload[5 : 5 + record_len]
    if len(body) < 4 or body[0] != 0x01:
        return ""
    hs_len = int.from_bytes(body[1:4], "big")
    hello = body[4 : 4 + hs_len]
    if len(hello) < 38:
        return ""
    offset = 34
    session_len = hello[offset]
    offset += 1 + session_len
    if offset + 2 > len(hello):
        return ""
    cipher_len = struct.unpack("!H", hello[offset : offset + 2])[0]
    offset += 2 + cipher_len
    if offset + 1 > len(hello):
        return ""
    comp_len = hello[offset]
    offset += 1 + comp_len
    if offset + 2 > len(hello):
        return ""
    ext_len = struct.unpack("!H", hello[offset : offset + 2])[0]
    offset += 2
    end = min(len(hello), offset + ext_len)
    while offset + 4 <= end:
        etype, elen = struct.unpack("!HH", hello[offset : offset + 4])
        offset += 4
        data = hello[offset : offset + elen]
        offset += elen
        if etype != 0 or len(data) < 5:
            continue
        name_type = data[2]
        name_len = struct.unpack("!H", data[3:5])[0]
        if name_type != 0:
            continue
        try:
            return data[5 : 5 + name_len].decode("idna")
        except UnicodeError:
            return ""
    return ""


def service_name(port: int) -> str:
    """Return a short well-known service name, or empty when unknown."""
    return WELL_KNOWN.get(port, "")


def flow_key(frame: Decoded) -> tuple[str, str, str, int, int]:
    """Return a bidirectional flow key with endpoints ordered."""
    left = (frame.src_ip, frame.src_port)
    right = (frame.dst_ip, frame.dst_port)
    if left <= right:
        return frame.src_ip, frame.dst_ip, frame.proto, frame.src_port, frame.dst_port
    return frame.dst_ip, frame.src_ip, frame.proto, frame.dst_port, frame.src_port
