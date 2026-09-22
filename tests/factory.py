"""Build tiny Ethernet/IPv4 pcap bytes for tests."""

from __future__ import annotations

import struct


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst = bytes.fromhex("ffffffffffff")
    src = bytes.fromhex("aabbccddeeff")
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_ip = bytes(int(part) for part in src.split("."))
    dst_ip = bytes(int(part) for part in dst.split("."))
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0, src_ip, dst_ip)
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def tcp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    offset_flags = (5 << 12) | 0x018
    header = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, offset_flags, 8192, 0, 0)
    return header + payload


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def http_get(host: str, path: str = "/") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def http_response(status: int, body: bytes = b"ok") -> bytes:
    return f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


def ipv6(nxt: int, payload: bytes, src: str = "2001:db8::1", dst: str = "2001:db8::2") -> bytes:
    src_ip = ip_bytes_v6(src)
    dst_ip = ip_bytes_v6(dst)
    header = bytes([0x60]) + bytes(3) + struct.pack("!H", len(payload)) + bytes([nxt, 64]) + src_ip + dst_ip
    return header + payload


def ip_bytes_v6(address: str) -> bytes:
    if address.startswith("2001:db8::"):
        tail = address[len("2001:db8::") :]
        if tail:
            value = int(tail, 16)
        else:
            value = 0
        return bytes([0x20, 0x01, 0x0D, 0xB8]) + value.to_bytes(12, "big")
    return bytes(16)


def icmp_echo(dst: str, icmp_type: int = 8) -> bytes:
    inner = ipv4("10.0.0.1", dst, 6, tcp(0, 0, b""))
    return bytes([icmp_type, 0]) + struct.pack("!HHH", 0, 1, 0) + inner


def fragment(nxt: int, payload: bytes) -> bytes:
    return bytes([nxt, 0, 0, 0]) + bytes(4) + payload


def hop_by_hop(nxt: int, payload: bytes) -> bytes:
    return bytes([nxt, 0]) + bytes(6) + payload


def pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    header = struct.pack("<IHhiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    body = b""
    for index, frame in enumerate(frames):
        body += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame))
        body += frame
    return header + body


def pcap_be(frames: list[bytes], linktype: int = 1, nanoseconds: bool = False) -> bytes:
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    header = struct.pack(">IHhiIII", magic, 2, 4, 0, 0, 65535, linktype)
    body = b""
    for index, frame in enumerate(frames):
        frac = 500_000_000 if nanoseconds else 500_000
        body += struct.pack(">IIII", 1_700_000_000 + index, frac, len(frame), len(frame))
        body += frame
    return header + body


def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    data = struct.pack("!H", 3 + len(sni_bytes)) + b"\x00" + struct.pack("!H", len(sni_bytes))
    data += sni_bytes
    ext = struct.pack("!HH", 0, len(data)) + data
    hello = (
        b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(ext)) + ext
    )
    hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _ts_value(sec: int, tsresol: int, frac: int = 0) -> int:
    scale = 10**tsresol if 1 <= tsresol <= 10 else 1_000_000
    return sec * scale + frac


def _epb(iid: int, ts: int, frame: bytes) -> bytes:
    body = struct.pack("<IIIII", iid, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame))
    body += frame + b"\x00" * ((4 - len(frame) % 4) % 4)
    return _block(0x00000006, body)


def pcapng(frames: list[bytes], linktype: int = 1, tsresol: int = 6) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = _block(0x0A0D0D0A, shb_body)
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    if tsresol != 6:
        idb_body += struct.pack("<HHB", 9, 1, tsresol)
        idb_body += b"\x00" * 3
    out += _block(0x00000001, idb_body)
    for index, frame in enumerate(frames):
        out += _epb(0, _ts_value(1_700_000_000 + index, tsresol, 250_000), frame)
    return out


def pcapng_spb(frames: list[bytes], linktype: int = 1) -> bytes:
    """pcapng using Simple Packet Blocks, which carry no timestamps."""
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = _block(0x0A0D0D0A, shb_body)
    out += _block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))
    for frame in frames:
        body = struct.pack("<I", len(frame)) + frame
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        out += _block(0x00000002, body)
    return out


def pcapng_multi(
    linktype_a: int, frames_a: list[bytes], linktype_b: int, frames_b: list[bytes]
) -> bytes:
    """pcapng with two interfaces carrying different link types."""
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = _block(0x0A0D0D0A, shb_body)
    out += _block(0x00000001, struct.pack("<HHI", linktype_a, 0, 65535))
    out += _block(0x00000001, struct.pack("<HHI", linktype_b, 0, 65535))
    for index, frame in enumerate(frames_a):
        out += _epb(0, _ts_value(1_700_000_000 + index, 6), frame)
    for index, frame in enumerate(frames_b):
        out += _epb(1, _ts_value(1_700_000_000 + index, 6), frame)
    return out
