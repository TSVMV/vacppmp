"""Read classic pcap and pcapng files into decoded frames."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .decode import Decoded, decode_frame
from .errors import ParseError

__all__ = ["Capture", "Packet", "open_capture"]

PCAP_MAGIC = {0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1}
PCAPNG_MAGIC = 0x1A2B3C4D
PCAPNG_BLOCK = 0x0A0D0D0A
PCAPNG_BLOCK_SWAP = 0x0D0A0A0D


@dataclass
class Packet:
    """One captured packet with timestamp and decoded layers."""

    index: int
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
    frame: Decoded


@dataclass
class Capture:
    """A fully loaded capture: packets plus file metadata."""

    path: str
    kind: str
    linktype: int
    packets: list[Packet]

    @property
    def count(self) -> int:
        return len(self.packets)


def open_capture(path: str | Path) -> Capture:
    """Open a pcap or pcapng file and decode every packet."""
    target = Path(path)
    if not target.is_file():
        raise ParseError(f"找不到捕获文件 {path}")
    data = target.read_bytes()
    if len(data) < 4:
        raise ParseError(f"文件过短，无法识别格式：{path}")
    magic32 = struct.unpack("<I", data[:4])[0]
    magic16 = struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0
    if magic32 in PCAP_MAGIC or magic16 in {0xA1B2, 0xD4C3}:
        kind, linktype, packets = _read_pcap(data)
    elif magic32 == PCAPNG_BLOCK or magic32 == PCAPNG_BLOCK_SWAP:
        kind, linktype, packets = _read_pcapng(data)
    else:
        raise ParseError(f"无法识别捕获格式（magic=0x{magic32:08x}）：{path}")
    return Capture(path=str(target), kind=kind, linktype=linktype, packets=packets)


def _endian(magic: int) -> str:
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        return "<"
    if magic in (0xD4C3B2A1, 0x4D3CB2A1):
        return ">"
    raise ParseError(f"未知 pcap magic 0x{magic:08x}")


def _read_pcap(data: bytes) -> tuple[str, int, list[Packet]]:
    if len(data) < 24:
        raise ParseError("pcap 文件头不完整")
    magic = struct.unpack("<I", data[:4])[0]
    endian = _endian(magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    packets: list[Packet] = []
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        if incl_len > 0x1000000 or offset + incl_len > len(data):
            break
        payload = data[offset : offset + incl_len]
        offset += incl_len
        usec = ts_frac // 1000 if nano else ts_frac
        packets.append(
            Packet(
                index=index,
                ts_sec=ts_sec,
                ts_usec=usec,
                incl_len=incl_len,
                orig_len=orig_len,
                frame=decode_frame(payload, linktype),
            )
        )
        index += 1
    return "pcap", linktype, packets


def _read_pcapng(data: bytes) -> tuple[str, int, list[Packet]]:
    packets: list[Packet] = []
    endian = "<"
    linktype = 1
    tsresol = 6
    offset = 0
    index = 0
    while offset + 12 <= len(data):
        block_type = struct.unpack(endian + "I", data[offset : offset + 4])[0]
        if offset == 0:
            endian = _pcapng_endian(data)
            block_type = struct.unpack(endian + "I", data[offset : offset + 4])[0]
        total_len = struct.unpack(endian + "I", data[offset + 4 : offset + 8])[0]
        if total_len < 12 or offset + total_len > len(data):
            break
        body = data[offset + 8 : offset + total_len - 4]
        if block_type == 0x0A0D0D0A:
            pass
        elif block_type == 0x00000001:
            if len(body) >= 4:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
            tsresol = _if_tsresol(body, endian)
        elif block_type == 0x00000006:
            packet, tsresol = _enhanced_packet(body, endian, linktype, tsresol, index)
            if packet is not None:
                packets.append(packet)
                index += 1
        elif block_type == 0x00000002:
            packet = _simple_packet(body, linktype, index)
            if packet is not None:
                packets.append(packet)
                index += 1
        offset += total_len
        if total_len % 4:
            break
    return "pcapng", linktype, packets


def _pcapng_endian(data: bytes) -> str:
    if len(data) < 16:
        return "<"
    magic = struct.unpack("<I", data[8:12])[0]
    if magic == PCAPNG_MAGIC:
        return "<"
    magic = struct.unpack(">I", data[8:12])[0]
    if magic == PCAPNG_MAGIC:
        return ">"
    return "<"


def _if_tsresol(body: bytes, endian: str) -> int:
    if len(body) < 8:
        return 6
    options = body[8:]
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos : pos + 4])
        pos += 4
        value = options[pos : pos + length]
        pos += length
        pad = (4 - (length % 4)) % 4
        pos += pad
        if code == 9 and value:
            return value[0]
        if code == 0:
            break
    return 6


def _enhanced_packet(
    body: bytes, endian: str, linktype: int, tsresol: int, index: int
) -> tuple[Packet | None, int]:
    if len(body) < 20:
        return None, tsresol
    ts_high, ts_low, caplen, origlen = struct.unpack(endian + "IIII", body[4:20])
    ts = (ts_high << 32) | ts_low
    scale = 10 ** (tsresol & 0x7F) if tsresol < 128 else 2 ** (tsresol & 0x7F)
    sec = ts // scale if scale else ts
    frac = ts % scale if scale else 0
    usec = int(frac * 1_000_000 / scale) if scale else 0
    payload = body[20 : 20 + caplen]
    if len(payload) < caplen:
        return None, tsresol
    packet = Packet(
        index=index,
        ts_sec=int(sec),
        ts_usec=usec,
        incl_len=caplen,
        orig_len=origlen,
        frame=decode_frame(payload, linktype),
    )
    return packet, tsresol


def _simple_packet(body: bytes, linktype: int, index: int) -> Packet | None:
    if len(body) < 4:
        return None
    origlen = struct.unpack("<I", body[:4])[0]
    payload = body[4:]
    return Packet(
        index=index,
        ts_sec=0,
        ts_usec=0,
        incl_len=len(payload),
        orig_len=origlen,
        frame=decode_frame(payload, linktype),
    )


def iter_packets(path: str | Path) -> Iterator[Packet]:
    """Yield packets from a capture file."""
    yield from open_capture(path).packets
