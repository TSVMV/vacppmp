"""Aggregate decoded packets into hosts, flows, protocols and names."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace

from .decode import Decoded, flow_key, service_name
from .pcap import Capture, Packet

__all__ = ["BUCKETS", "Flow", "Host", "Report", "build_report", "select"]

BUCKETS = 40


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
    src_port: int
    dst: str
    dst_port: int
    proto: str
    packets: int = 0
    bytes: int = 0
    names: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)
    ts_first: float = 0.0
    ts_last: float = 0.0


@dataclass
class Report:
    path: str
    kind: str
    packet_count: int
    byte_count: int
    first_ts: float
    last_ts: float
    ts_known: bool
    protocols: Counter
    transports: Counter
    hosts: dict[str, Host]
    flows: list[Flow]
    names: Counter
    http_hosts: Counter
    http_status: Counter
    tls_sni: Counter
    ports: Counter
    flags: Counter
    icmps: Counter
    icmp_targets: Counter
    conversations: list[tuple[str, str, int, int]]
    timeline: list[tuple[int, int]]
    timeline_step: float

    @property
    def duration(self) -> float:
        if not self.ts_known or self.last_ts <= self.first_ts:
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


def _timeline(packets: list[Packet], ts_known: bool) -> tuple[list[tuple[int, int]], float]:
    """Bucket bytes and packets into fixed slots across the capture window."""
    rows = [(_ts(packet), packet.frame.length or packet.incl_len) for packet in packets if packet.ts_valid]
    if not ts_known or not rows:
        return [], 0.0
    start = min(ts for ts, _size in rows)
    end = max(ts for ts, _size in rows)
    if end <= start:
        return [(0, 0)] * BUCKETS, 0.0
    step = (end - start) / BUCKETS
    buckets = [[0, 0] for _ in range(BUCKETS)]
    for stamp, size in rows:
        index = min(BUCKETS - 1, int((stamp - start) / step))
        buckets[index][0] += size
        buckets[index][1] += 1
    return buckets, step


def build_report(capture: Capture) -> Report:
    """Turn a capture into hosts, conversations and protocol counts."""
    protocols: Counter = Counter()
    transports: Counter = Counter()
    hosts: dict[str, Host] = {}
    flows: dict[tuple, Flow] = {}
    names: Counter = Counter()
    http_hosts: Counter = Counter()
    http_status: Counter = Counter()
    tls_sni: Counter = Counter()
    ports: Counter = Counter()
    flags: Counter = Counter()
    icmps: Counter = Counter()
    icmp_targets: Counter = Counter()
    pair_bytes: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    byte_count = 0
    first_ts = 0.0
    last_ts = 0.0
    stamped = False

    for packet in capture.packets:
        frame = packet.frame
        stamp = _ts(packet)
        if packet.ts_valid:
            if not stamped:
                first_ts = stamp
                stamped = True
            else:
                first_ts = min(first_ts, stamp)
            last_ts = max(last_ts, stamp)
        size = frame.length or packet.incl_len
        byte_count += size
        proto = frame.proto or frame.ethertype or frame.link or "unknown"
        protocols[proto] += 1
        if frame.transport:
            transports[frame.transport] += 1
        for name in _names(frame):
            names[name] += 1
        if frame.http_host:
            http_hosts[frame.http_host] += 1
        if frame.http_status:
            http_status[frame.http_status] += 1
        if frame.tls_sni:
            tls_sni[frame.tls_sni] += 1
        for port in {frame.src_port, frame.dst_port}:
            if port:
                ports[port] += 1
        if frame.tcp_flags:
            flags[frame.tcp_flags] += 1
        if frame.icmp_type:
            icmps[frame.icmp_type] += 1
            if frame.icmp_target:
                icmp_targets[frame.icmp_target] += 1
        _touch_host(hosts, frame.src_ip, size, sent=True, port=frame.src_port, proto=proto, names=_names(frame))
        _touch_host(hosts, frame.dst_ip, size, sent=False, port=frame.dst_port, proto=proto, names=_names(frame))
        if frame.icmp_target:
            _touch_host(
                hosts,
                frame.icmp_target,
                size,
                sent=frame.icmp_target == frame.src_ip,
                port=0,
                proto="ICMP",
                names=[],
            )
        if frame.src_ip and frame.dst_ip:
            key = flow_key(frame)
            flow = flows.get(key)
            if flow is None:
                flow = Flow(*key)
                flows[key] = flow
            flow.packets += 1
            flow.bytes += size
            flow.names.update(_names(frame))
            if frame.tcp_flags:
                flow.flags.add(frame.tcp_flags)
            if packet.ts_valid:
                if not flow.ts_first:
                    flow.ts_first = stamp
                flow.ts_last = max(flow.ts_last, stamp)
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
    timeline, step = _timeline(capture.packets, capture.ts_known)
    return Report(
        path=capture.path,
        kind=capture.kind,
        packet_count=capture.count,
        byte_count=byte_count,
        first_ts=first_ts,
        last_ts=last_ts,
        ts_known=capture.ts_known,
        protocols=protocols,
        transports=transports,
        hosts=hosts,
        flows=ordered_flows,
        names=names,
        http_hosts=http_hosts,
        http_status=http_status,
        tls_sni=tls_sni,
        ports=ports,
        flags=flags,
        icmps=icmps,
        icmp_targets=icmp_targets,
        conversations=conversations,
        timeline=timeline,
        timeline_step=step,
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


def _matches(frame: Decoded, host: str, port: int, proto: str) -> bool:
    if host and host not in {frame.src_ip, frame.dst_ip, frame.icmp_target}:
        return False
    if port and port not in {frame.src_port, frame.dst_port}:
        return False
    if proto:
        wanted = proto.upper()
        if frame.proto == wanted or frame.transport == wanted:
            return True
        if wanted in {"HTTPS", "TLS"}:
            return bool(frame.tls_sni)
        if wanted == "DNS":
            return bool(frame.dns_names)
        if wanted == "HTTP":
            return bool(frame.http_host or frame.http_status)
        return False
    return True


def select(capture: Capture, host: str = "", port: int = 0, proto: str = "") -> Capture:
    """Return a copy of the capture keeping only matching packets."""
    if not (host or port or proto):
        return capture
    kept = [packet for packet in capture.packets if _matches(packet.frame, host, port, proto)]
    return replace(capture, packets=kept)


def port_label(port: int) -> str:
    """Return a human label for a port number, e.g. 443 -> https."""
    return service_name(port) or str(port)
