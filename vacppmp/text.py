"""Plain-text terminal summary of a capture report."""

from __future__ import annotations

from datetime import UTC, datetime

from .stats import BUCKETS, Report, port_label

__all__ = ["render"]

SPARK = " ▁▂▃▄▅▆▇█"


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.1f} GB"


def _stamp(ts: float) -> str:
    if ts <= 0:
        return "-"
    return datetime.fromtimestamp(ts, tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _bar(value: int, total: int, width: int = 14) -> str:
    if total <= 0:
        return "-" * width
    filled = min(width, round(width * value / total))
    return "#" * filled + "-" * (width - filled)


def _spark(values: list[int]) -> str:
    if not values:
        return ""
    peak = max(values)
    if peak <= 0:
        return SPARK[0] * len(values)
    step = len(SPARK) - 2
    return "".join(SPARK[min(len(SPARK) - 1, int(1 + step * value / peak))] for value in values)


def render(report: Report, top: int = 12) -> str:
    """Return a Chinese terminal summary for a report."""
    timing = f"{report.duration:.3f} 秒" if report.ts_known else "未知（该格式不含时间戳）"
    span = f"    首包 {_stamp(report.first_ts)}  末包 {_stamp(report.last_ts)}" if report.ts_known else ""
    lines = [
        f"文件：{report.path}",
        f"格式：{report.kind}    包数：{report.packet_count}    字节：{_size(report.byte_count)}",
        f"时长：{timing}    主机：{len(report.hosts)}    会话：{len(report.conversations)}{span}",
        "",
        "传输层",
    ]
    tx_total = sum(report.transports.values()) or 1
    for name, count in report.transports.most_common(top):
        lines.append(f"  {_bar(count, tx_total)}  {count:6d}  {name}")
    lines.append("")
    lines.append("应用协议")
    proto_total = sum(report.protocols.values()) or 1
    for name, count in report.protocols.most_common(top):
        lines.append(f"  {_bar(count, proto_total)}  {count:6d}  {name}")
    if report.timeline:
        peak_bytes = max(bytes_ for bytes_, _packets in report.timeline) or 1
        lines.append("")
        lines.append(
            f"时间分布（{BUCKETS} 段，峰值 {_size(peak_bytes)}/段）"
        )
        lines.append(f"  {_spark([bytes_ for bytes_, _p in report.timeline])}")
        lines.append(f"  {_spark([packets for _b, packets in report.timeline])}")
    if report.ports:
        lines.append("")
        lines.append("端口 / 服务")
        for port, count in report.ports.most_common(top):
            lines.append(f"  {count:6d}  {_bar(count, report.ports.most_common(1)[0][1])}  {port_label(port)} ({port})")
    lines.append("")
    lines.append("通信对（按字节）")
    for src, dst, total, _fwd in report.conversations[:top]:
        lines.append(f"  {_size(total):>10}  {src}  <->  {dst}")
    if report.hosts:
        lines.append("")
        lines.append("主机（按字节）")
        for host in sorted(report.hosts.values(), key=lambda item: item.bytes, reverse=True)[:top]:
            names = ",".join(sorted(host.names)[:2])
            tail = f"  {names}" if names else ""
            lines.append(
                f"  {_size(host.bytes):>10}  {host.packets:6d} pkts  "
                f"发 {_size(host.sent):>8} / 收 {_size(host.received):>8}  {host.ip}{tail}"
            )
    if report.flags:
        lines.append("")
        lines.append("TCP 标志位")
        for name, count in report.flags.most_common(top):
            lines.append(f"  {count:6d}  {name}")
    if report.http_status:
        lines.append("")
        lines.append("HTTP 状态码")
        for status, count in report.http_status.most_common(top):
            lines.append(f"  {count:6d}  {status}")
    if report.icmps:
        lines.append("")
        lines.append("ICMP 类型")
        label = {
            0: "echo-reply",
            3: "unreachable",
            5: "redirect",
            8: "echo-request",
            11: "exceeded",
            128: "v6 echo-request",
            129: "v6 echo-reply",
        }
        for icmp_type, count in report.icmps.most_common(top):
            lines.append(f"  {count:6d}  type {icmp_type} ({label.get(icmp_type, '?')})")
        if report.icmp_targets:
            for target, count in report.icmp_targets.most_common(top):
                lines.append(f"  {count:6d}  ping -> {target}")
    if report.names:
        lines.append("")
        lines.append("解析到的名字（DNS / HTTP Host / TLS SNI）")
        for name, count in report.names.most_common(top):
            lines.append(f"  {count:6d}  {name}")
    if report.flows:
        lines.append("")
        lines.append("流（按字节）")
        for flow in report.flows[:top]:
            sport = f":{flow.src_port}" if flow.src_port else ""
            dport = f":{flow.dst_port}" if flow.dst_port else ""
            extra = f"  ({', '.join(sorted(flow.names)[:3])})" if flow.names else ""
            lines.append(
                f"  {_size(flow.bytes):>10}  {flow.packets:5d} pkts  "
                f"{flow.proto:8}  {flow.src}{sport} -> {flow.dst}{dport}{extra}"
            )
    lines.append("")
    return "\n".join(lines)
