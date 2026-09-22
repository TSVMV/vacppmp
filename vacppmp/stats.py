"""Aggregate decoded packets into hosts, flows, protocols and names."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .decode import Decoded, flow_key
from .pcap import Capture, Packet

__all__ = ["Flow", "Host", "Report", "build_report"]


@dataclass
class Host:
    ip: str
    packets: int = 0
    bytes: int = 0
    sent: int = 0
    received: int = 0
    ports: set[int] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)


@dataclass
class Flow:
    src: str
    dst: str
    proto: str
    src_port: int
    dst_port: int
    packets: int = 0
    bytes: int = 0
    names: set[str] = field(default_factory=set)


@dataclass
class Report:
    path: str
    kind: str
    packet_count: int
    byte_count: int
    first_ts: float
    last_ts: float
    protocols: Counter
    hosts: dict[str, Host]
    flows: list[Flow]
    names: Counter
    http_hosts: Counter
    tls_sni: Counter
    conversations: list[tuple[str, str, int, int]]

    @property
    def duration(self) -> float:
        if self.last_ts <= self.first_ts:
            return 0.0
        return self.last_ts - self.first_ts


def _ts(packet: Packet) -> float:
    return packet.ts_sec + packet.ts_usec / 1_000_000


def _names(frame: Decoded) -> list[str]:
    found = list(frame.dns_names)
    if frame.http_host:
        found.append(frame.http_host)
    if frame.tls_sni:
        found.append(frame.tls_sni)
    return found


def build_report(capture: Capture) -> Report:
    """Turn a capture into hosts, conversations and protocol counts."""
    protocols: Counter = Counter()
    hosts: dict[str, Host] = {}
    flows: dict[tuple, Flow] = {}
    names: Counter = Counter()
    http_hosts: Counter = Counter()
    tls_sni: Counter = Counter()
    pair_bytes: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    byte_count = 0
    first_ts = 0.0
    last_ts = 0.0

    for packet in capture.packets:
        frame = packet.frame
        stamp = _ts(packet)
        if first_ts == 0.0 or stamp < first_ts:
            first_ts = stamp
        last_ts = max(last_ts, stamp)
        size = frame.length or packet.incl_len
        byte_count += size
        proto = frame.proto or frame.ethertype or frame.link or "unknown"
        protocols[proto] += 1
        for name in _names(frame):
            names[name] += 1
        if frame.http_host:
            http_hosts[frame.http_host] += 1
        if frame.tls_sni:
            tls_sni[frame.tls_sni] += 1
        _touch_host(hosts, frame.src_ip, size, sent=True, port=frame.src_port, proto=proto, names=_names(frame))
        _touch_host(hosts, frame.dst_ip, size, sent=False, port=frame.dst_port, proto=proto, names=_names(frame))
        if frame.src_ip and frame.dst_ip:
            key = flow_key(frame)
            flow = flows.get(key)
            if flow is None:
                flow = Flow(*key)
                flows[key] = flow
            flow.packets += 1
            flow.bytes += size
            flow.names.update(_names(frame))
            left, right = sorted((frame.src_ip, frame.dst_ip))
            bucket = pair_bytes[(left, right)]
            if frame.src_ip == left:
                bucket[0] += size
            else:
                bucket[1] += size

    conversations = [
        (src, dst, total[0] + total[1], total[0])
        for (src, dst), total in pair_bytes.items()
    ]
    conversations.sort(key=lambda item: item[2], reverse=True)
    ordered_flows = sorted(flows.values(), key=lambda item: item.bytes, reverse=True)
    return Report(
        path=capture.path,
        kind=capture.kind,
        packet_count=capture.count,
        byte_count=byte_count,
        first_ts=first_ts,
        last_ts=last_ts,
        protocols=protocols,
        hosts=hosts,
        flows=ordered_flows,
        names=names,
        http_hosts=http_hosts,
        tls_sni=tls_sni,
        conversations=conversations,
    )


def _touch_host(
    hosts: dict[str, Host],
    ip: str,
    size: int,
    *,
    sent: bool,
    port: int,
    proto: str,
    names: list[str],
) -> None:
    if not ip:
        return
    host = hosts.get(ip)
    if host is None:
        host = Host(ip=ip)
        hosts[ip] = host
    host.packets += 1
    host.bytes += size
    if sent:
        host.sent += size
    else:
        host.received += size
    if port:
        host.ports.add(port)
    host.protocols[proto] += 1
    host.names.update(names)
