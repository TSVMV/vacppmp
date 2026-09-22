"""Read classic pcap and pcapng files into decoded frames."""

from __future__ import annotations

import gzip
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .decode import Decoded, decode_frame
from .errors import ParseError

__all__ = ["Capture", "Packet", "iter_packets", "open_capture"]

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
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
    ts_valid: bool = True


@dataclass
class Capture:
    """A fully loaded capture: packets plus file metadata."""

    path: str
    kind: str
    linktype: int
    packets: list[Packet]
    ts_known: bool = True
    interfaces: dict[int, int] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.packets)

    @property
    def dropped_packets(self) -> int:
        return sum(1 for packet in self.packets if not packet.frame.proto)

    @property
    def first_ts(self) -> float:
        stamps = [packet.ts_sec + packet.ts_usec / 1_000_000 for packet in self.packets if packet.ts_valid]
        return min(stamps) if stamps else 0.0

    @property
    def last_ts(self) -> float:
        stamps = [packet.ts_sec + packet.ts_usec / 1_000_000 for packet in self.packets if packet.ts_valid]
        return max(stamps) if stamps else 0.0


def _decompress(raw: bytes) -> tuple[bytes, bool]:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw), True
        except (OSError, EOFError) as exc:
            raise ParseError(f"gzip 解压失败：{exc}") from exc
    return raw, False


def _pcap_detect(data: bytes) -> tuple[str, bool] | None:
    """Return (endian, nanoseconds) for a classic pcap header.

    The magic bytes are compared raw: the four bytes of the magic are not
    a palindrome, so the same integer can be read under both byte orders,
    and only the byte sequence itself says which order the writer used.
    """
    return PCAP_MAGICS.get(data[:4])


def open_capture(path: str | Path) -> Capture:
    """Open a pcap or pcapng file and decode every packet."""
    target = Path(path)
    if not target.is_file():
        raise ParseError(f"找不到捕获文件 {path}")
    data, gzipped = _decompress(target.read_bytes())
    if len(data) < 4:
        raise ParseError(f"文件过短，无法识别格式：{path}")
    note = "（gzip 压缩）" if gzipped else ""
    pcap = _pcap_detect(data)
    if pcap is not None:
        endian, nano = pcap
        kind, linktype, packets, ts_known = _read_pcap(data, endian, nano)
    else:
        magic32 = struct.unpack("<I", data[:4])[0]
        if magic32 not in (PCAPNG_BLOCK, PCAPNG_BLOCK_SWAP):
            raise ParseError(f"无法识别捕获格式（magic=0x{magic32:08x}）：{path}")
        kind, linktype, packets, ts_known, interfaces = _read_pcapng(data)
        return Capture(
            path=f"{target}{note}",
            kind=kind,
            linktype=linktype,
            packets=packets,
            ts_known=ts_known,
            interfaces=interfaces,
        )
    return Capture(
        path=f"{target}{note}",
        kind=kind,
        linktype=linktype,
        packets=packets,
        ts_known=ts_known,
    )


def _read_pcap(data: bytes, endian: str, nano: bool) -> tuple[str, int, list[Packet], bool]:
    if len(data) < 24:
        raise ParseError("pcap 文件头不完整")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
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
    return "pcap", linktype, packets, True


def _read_pcapng(data: bytes) -> tuple[str, int, list[Packet], bool, dict[int, int]]:
    packets: list[Packet] = []
    endian = "<"
    interfaces: dict[int, int] = {}
    resolutions: dict[int, int] = {}
    default_link = 1
    default_res = 6
    ts_known = True
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
        if block_type == PCAPNG_BLOCK:
            pass
        elif block_type == 0x00000001:
            if len(body) >= 4:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
            else:
                linktype = default_link
            iid = len(interfaces)
            interfaces[iid] = linktype
            resolutions[iid] = _if_tsresol(body, endian)
            default_link, default_res = linktype, resolutions[iid]
        elif block_type == 0x00000006 and len(body) >= 4:
            iid = struct.unpack(endian + "I", body[0:4])[0]
            packet = _enhanced_packet(
                body,
                endian,
                interfaces.get(iid, default_link),
                resolutions.get(iid, default_res),
                index,
            )
            if packet is not None:
                packets.append(packet)
                index += 1
        elif block_type == 0x00000002:
            packet = _simple_packet(body, default_link, index)
            if packet is not None:
                packets.append(packet)
                ts_known = False
                index += 1
        offset += total_len
        if total_len % 4:
            break
    if not interfaces:
        interfaces = {0: default_link}
    return "pcapng", default_link, packets, ts_known, interfaces


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


def _ts_scale(tsresol: int) -> int:
    if tsresol >= 128:
        return 2 ** (tsresol & 0x7F)
    if 1 <= tsresol <= 10:
        return 10**tsresol
    return 1_000_000


def _enhanced_packet(body: bytes, endian: str, linktype: int, tsresol: int, index: int) -> Packet | None:
    if len(body) < 20:
        return None
    ts_high, ts_low, caplen, origlen = struct.unpack(endian + "IIII", body[4:20])
    ts = (ts_high << 32) | ts_low
    scale = _ts_scale(tsresol)
    payload = body[20 : 20 + caplen]
    if len(payload) < caplen:
        return None
    packet = Packet(
        index=index,
        ts_sec=int(ts // scale),
        ts_usec=int((ts % scale) * 1_000_000 / scale),
        incl_len=caplen,
        orig_len=origlen,
        frame=decode_frame(payload, linktype),
    )
    return packet


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
        ts_valid=False,
    )


def iter_packets(path: str | Path) -> Iterator[Packet]:
    """Yield packets from a capture file."""
    yield from open_capture(path).packets
