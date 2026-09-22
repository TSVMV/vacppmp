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


def pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    body = b""
    for index, frame in enumerate(frames):
        body += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame))
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


def pcapng(frames: list[bytes], linktype: int = 1, tsresol: int = 6) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = _block(0x0A0D0D0A, shb_body)
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    if tsresol != 6:
        idb_body += struct.pack("<HHB", 9, 1, tsresol)
        idb_body += b"\x00" * 3
    out += _block(0x00000001, idb_body)
    for index, frame in enumerate(frames):
        ts = (1_700_000_000 + index) << 32
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame))
        body += frame
        pad = (4 - (len(frame) % 4)) % 4
        body += b"\x00" * pad
        out += _block(0x00000006, body)
    return out
