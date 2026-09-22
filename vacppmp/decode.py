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
    transport: str = ""
    proto: str = ""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    dns_names: list[str] = field(default_factory=list)
    http_host: str = ""
    http_method: str = ""
    http_status: int = 0
    tls_sni: str = ""
    tcp_flags: str = ""
    arp_spa: str = ""
    arp_tpa: str = ""
    icmp_type: int = 0
    icmp_code: int = 0
    icmp_target: str = ""


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _fmt_ipv4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _fmt_ipv6(raw: bytes) -> str:
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
    frame.src_ip = _fmt_ipv4(payload[12:16])
    frame.dst_ip = _fmt_ipv4(payload[16:20])
    frame.transport = IP_PROTO.get(proto, "")
    body = payload[ihl:]
    if proto == 6:
        return _tcp(body, frame)
    if proto == 17:
        return _udp(body, frame)
    if proto == 1:
        return _icmp(body, frame)
    if not frame.proto:
        frame.proto = IP_PROTO.get(proto) or f"ip-{proto}"
    return frame


def _ipv6(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 40:
        return frame
    if payload[0] >> 4 != 6:
        return frame
    nxt = payload[6]
    frame.ip_version = 6
    frame.src_ip = _fmt_ipv6(payload[8:24])
    frame.dst_ip = _fmt_ipv6(payload[24:40])
    offset = 40
    for _ in range(8):
        if nxt not in (0, 44, 60):
            break
        if offset + 2 > len(payload):
            break
        head_type = payload[offset]
        nxt = head_type
        if head_type == 44:
            offset = min(len(payload), offset + 8)
            continue
        offset = min(len(payload), offset + (payload[offset + 1] + 1) * 8)
    frame.transport = IP_PROTO.get(nxt, "")
    body = payload[offset:]
    if nxt == 6:
        return _tcp(body, frame)
    if nxt == 17:
        return _udp(body, frame)
    if nxt == 58:
        return _icmpv6(body, frame)
    if not frame.proto:
        frame.proto = IP_PROTO.get(nxt) or f"ip-{nxt}"
    return frame


def _arp(payload: bytes, frame: Decoded) -> Decoded:
    frame.transport = "ARP"
    frame.proto = "ARP"
    if len(payload) < 28:
        return frame
    frame.arp_spa = _fmt_ipv4(payload[14:18])
    frame.arp_tpa = _fmt_ipv4(payload[24:28])
    frame.src_ip = frame.arp_spa
    frame.dst_ip = frame.arp_tpa
    return frame


def _tcp(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 20:
        return frame
    frame.src_port, frame.dst_port = struct.unpack("!HH", payload[0:4])
    frame.transport = "TCP"
    frame.tcp_flags = _tcp_flags(payload[13])
    offset = ((payload[12] >> 4) & 0x0F) * 4
    body = payload[offset:] if offset >= 20 else payload[20:]
    _app(frame, body)
    return frame


def _udp(payload: bytes, frame: Decoded) -> Decoded:
    if len(payload) < 8:
        return frame
    frame.src_port, frame.dst_port = struct.unpack("!HH", payload[0:4])
    frame.transport = "UDP"
    _app(frame, payload[8:])
    return frame


def _icmp(payload: bytes, frame: Decoded) -> Decoded:
    """Decode an IPv4 ICMP packet; echo carries the real target address."""
    frame.transport = "ICMP"
    frame.proto = "ICMP"
    if len(payload) < 4:
        return frame
    frame.icmp_type = payload[0]
    frame.icmp_code = payload[1]
    if frame.icmp_type in (8, 0) and len(payload) >= 28:
        frame.icmp_target = _fmt_ipv4(payload[24:28])
    return frame


def _icmpv6(payload: bytes, frame: Decoded) -> Decoded:
    frame.transport = "ICMPv6"
    frame.proto = "ICMPv6"
    if len(payload) < 4:
        return frame
    frame.icmp_type = payload[0]
    frame.icmp_code = payload[1]
    if frame.icmp_type in (128, 129) and len(payload) >= 48:
        frame.icmp_target = _fmt_ipv6(payload[32:48])
    return frame


def _tcp_flags(raw: int) -> str:
    names = [("NS", 1), ("CWR", 2), ("ECE", 4), ("URG", 8), ("ACK", 16), ("PSH", 32), ("RST", 64), ("SYN", 128)]
    out = [label for label, mask in names if raw & mask]
    return "".join(out) if out else "NONE"


def _app(frame: Decoded, body: bytes) -> None:
    ports = {frame.src_port, frame.dst_port}
    if 53 in ports:
        names = _dns_names(body)
        if names:
            frame.dns_names = names
            frame.proto = "DNS"
            return
    host, method, status, is_http = _http(body)
    if is_http:
        frame.http_host = host
        frame.http_method = method
        frame.http_status = status
        frame.proto = "HTTP"
        return
    if 443 in ports:
        sni = _tls_sni(body)
        if sni:
            frame.tls_sni = sni
        frame.proto = "TLS"
        return
    service = WELL_KNOWN.get(frame.dst_port) or WELL_KNOWN.get(frame.src_port)
    if service and not frame.proto:
        frame.proto = service.upper()
    if not frame.proto:
        frame.proto = frame.transport



def _dns_names(payload: bytes) -> list[str]:
    if len(payload) < 12:
        return []
    flags = struct.unpack("!H", payload[2:4])[0]
    questions = struct.unpack("!H", payload[4:6])[0]
    answers = struct.unpack("!H", payload[6:8])[0]
    names: list[str] = []
    offset = 12
    if questions:
        for _ in range(min(questions, 64)):
            name, offset = _dns_label(payload, offset)
            if offset + 4 > len(payload):
                break
            if name and name not in names:
                names.append(name)
            offset += 4
    if not names and (flags & 0x8000) and answers and len(payload) >= 16:
        name, _ = _dns_label(payload, offset)
        if name:
            names.append(name)
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


def _http(payload: bytes) -> tuple[str, str, int, bool]:
    if not payload:
        return "", "", 0, False
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        try:
            text = payload.split(b"\n\n", 1)[0].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            return "", "", 0, False
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        return "", "", 0, False
    parts = lines[0].split()
    method = ""
    status = 0
    is_http = False
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        is_http = True
        if parts[1].isdigit():
            status = int(parts[1])
    elif len(parts) >= 3 and parts[2].startswith("HTTP/") and parts[0].isalpha():
        is_http = True
        method = parts[0]
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return host, method, status, is_http


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


def flow_key(frame: Decoded) -> tuple[str, int, str, int, str]:
    """Return a bidirectional flow key ordered by endpoint, transport-stable.

    The key only uses addresses and ports. Application labels (DNS, TLS, ...)
    differ between the handshake packet and the data packets of the same
    connection, so folding them into the key would split one flow in two.
    """
    left = (frame.src_ip, frame.src_port)
    right = (frame.dst_ip, frame.dst_port)
    proto = frame.transport or frame.proto or frame.ethertype or ""
    if left <= right:
        return frame.src_ip, frame.src_port, frame.dst_ip, frame.dst_port, proto
    return frame.dst_ip, frame.dst_port, frame.src_ip, frame.src_port, proto
