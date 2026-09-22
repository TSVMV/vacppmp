"""Plain-text terminal summary of a capture report."""

from __future__ import annotations

from .stats import Report

__all__ = ["render"]


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.1f} GB"


def _bar(value: int, total: int, width: int = 16) -> str:
    if total <= 0:
        return "-" * width
    filled = min(width, round(width * value / total))
    return "#" * filled + "-" * (width - filled)


def render(report: Report, top: int = 12) -> str:
    """Return a Chinese terminal summary for a report."""
    lines = [
        f"文件：{report.path}",
        f"格式：{report.kind}    包数：{report.packet_count}    字节：{_size(report.byte_count)}",
        f"时长：{report.duration:.3f} 秒    主机：{len(report.hosts)}    会话：{len(report.conversations)}",
        "",
        "协议分布",
    ]
    proto_total = sum(report.protocols.values()) or 1
    for name, count in report.protocols.most_common(top):
        lines.append(f"  {_bar(count, proto_total)}  {count:6d}  {name}")
    lines.append("")
    lines.append("通信对（按字节）")
    for src, dst, total, _fwd in report.conversations[:top]:
        lines.append(f"  {_size(total):>10}  {src}  <->  {dst}")
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
