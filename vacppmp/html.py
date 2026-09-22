"""Self-contained HTML report with SVG conversation map."""

from __future__ import annotations

import html
import math
from datetime import UTC, datetime

from .stats import BUCKETS, Report, port_label

__all__ = ["render"]

PALETTE = [
    "#3d8bfd",
    "#63e6be",
    "#ffd43b",
    "#ff8787",
    "#da77f2",
    "#74c0fc",
    "#69db7c",
    "#ffa94d",
    "#91a7ff",
    "#66d9e8",
]


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _stamp(ts: float) -> str:
    if ts <= 0:
        return "-"
    return datetime.fromtimestamp(ts, tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _color(index: int) -> str:
    return PALETTE[index % len(PALETTE)]


def _layout(report: Report, width: int = 920, height: int = 560) -> tuple[str, int]:
    hosts = sorted(report.hosts.values(), key=lambda item: item.bytes, reverse=True)[:36]
    if not hosts:
        return '<text x="40" y="40" fill="#8b949e">没有可绘制的 IP 主机</text>', height
    count = len(hosts)
    cx, cy = width / 2, height / 2
    radius = min(width, height) * 0.36
    positions = {}
    for index, host in enumerate(hosts):
        angle = (2 * math.pi * index / count) - math.pi / 2
        positions[host.ip] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle), host)
    max_bytes = max(host.bytes for host in hosts) or 1
    allowed = set(positions)
    edges = [
        (src, dst, total)
        for src, dst, total, _fwd in report.conversations
        if src in allowed and dst in allowed
    ]
    max_edge = max((total for *_, total in edges), default=1)
    parts: list[str] = []
    for src, dst, total in edges:
        x1, y1, _ = positions[src]
        x2, y2, _ = positions[dst]
        width_px = 1.2 + 6.0 * (total / max_edge)
        opacity = 0.25 + 0.5 * (total / max_edge)
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#58a6ff" stroke-width="{width_px:.2f}" stroke-opacity="{opacity:.2f}"/>'
        )
    for index, (ip, (x, y, host)) in enumerate(positions.items()):
        r = 8 + 18 * math.sqrt(host.bytes / max_bytes)
        label = ip
        if host.names:
            label = min(host.names)[:28]
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{_color(index)}" opacity="0.92"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y + r + 14:.1f}" text-anchor="middle" '
            f'fill="#e6edf3" font-size="11">{_esc(label)}</text>'
        )
        parts.append(
            f'<title>{_esc(ip)}  {_esc(_size(host.bytes))}  {_esc(host.packets)} pkts</title>'
        )
    svg_height = height + 24
    svg = (
        f'<svg viewBox="0 0 {width} {svg_height}" width="100%" '
        f'preserveAspectRatio="xMidYMid meet" role="img" '
        f'aria-label="主机通信图">'
        + "".join(parts)
        + "</svg>"
    )
    return svg, svg_height


def _timeline_svg(report: Report, width: int = 1040, height: int = 200) -> str:
    """Render bytes and packets per bucket as two stacked SVG areas."""
    if not report.timeline:
        return "<p class='sub'>该格式不含时间戳，无法绘制时间分布</p>"
    series = report.timeline
    if len(series) == 1:
        series = series + [[0, 0]]
    pad_left, pad_right, pad_top, pad_bottom = 56, 16, 14, 30
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    slots = len(series)
    bar_w = plot_w / slots
    max_bytes = max(b for b, _p in series) or 1
    max_pkts = max(p for _b, p in series) or 1
    parts = [
        (
            f'<svg viewBox="0 0 {width} {height}" width="100%" preserveAspectRatio="xMidYMid meet" '
            f'role="img" aria-label="时间分布">'
        )
    ]
    for bucket, (bytes_, packets) in enumerate(series):
        x = pad_left + bucket * bar_w
        h1 = plot_h * bytes_ / max_bytes
        h2 = plot_h * packets / max_pkts
        parts.append(
            f'<rect x="{x:.2f}" y="{pad_top + plot_h - h1:.2f}" width="{max(1.0, bar_w * 0.62):.2f}" '
            f'height="{max(0.0, h1):.2f}" fill="#58a6ff" opacity="0.85">'
            f'<title>{_stamp(report.first_ts + (bucket / (slots - 1)) * report.duration)}'
            f'  {_esc(_size(bytes_))}  {packets} pkts</title></rect>'
        )
        parts.append(
            f'<rect x="{x + max(1.0, bar_w * 0.62) + 1:.2f}" y="{pad_top + plot_h - h2:.2f}" '
            f'width="{max(1.0, bar_w * 0.24):.2f}" height="{max(0.0, h2):.2f}" '
            f'fill="#63e6be" opacity="0.75">'
            f'<title>{_esc(_size(bytes_))}  {packets} pkts</title></rect>'
        )
    parts.append(
        f'<text x="{pad_left}" y="{pad_top + 10}" fill="#8b949e" font-size="11">峰值 {_esc(_size(max_bytes))} / 段</text>'
    )
    parts.append(
        f'<line x1="{pad_left}" y1="{pad_top + plot_h}" x2="{width - pad_right}" y2="{pad_top + plot_h}" '
        f'stroke="#30363d"/>'
    )
    start, end = _stamp(report.first_ts), _stamp(report.last_ts)
    parts.append(
        f'<text x="{pad_left}" y="{height - 8}" fill="#8b949e" font-size="11">{_esc(start)}</text>'
    )
    parts.append(
        f'<text x="{width - pad_right}" y="{height - 8}" text-anchor="end" fill="#8b949e" '
        f'font-size="11">{_esc(end)}</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def _icmp_label(icmp_type: int) -> str:
    labels = {
        0: "echo-reply",
        3: "unreachable",
        5: "redirect",
        8: "echo-request",
        11: "exceeded",
        128: "v6 echo-request",
        129: "v6 echo-reply",
        135: "v6 destination-unreachable",
    }
    return labels.get(icmp_type, "?")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_esc(item)}</th>" for item in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{_esc(item)}</td>" for item in row)
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render(report: Report, top: int = 20) -> str:
    """Return a standalone HTML document for the report."""
    svg, _ = _layout(report)
    proto_total = sum(report.protocols.values()) or 1
    proto_rows = [
        [name, str(count), f"{100 * count / proto_total:.1f}%"]
        for name, count in report.protocols.most_common(top)
    ]
    tx_rows = [
        [name, str(count), f"{100 * count / sum(report.transports.values()) or 1:.1f}%"]
        for name, count in report.transports.most_common(top)
    ]
    host_rows = []
    for host in sorted(report.hosts.values(), key=lambda item: item.bytes, reverse=True)[:top]:
        host_rows.append(
            [
                host.ip,
                _size(host.bytes),
                str(host.packets),
                ",".join(str(port) for port in sorted(host.ports)[:8]),
                ", ".join(sorted(host.names)[:3]),
            ]
        )
    flow_rows = []
    for flow in report.flows[:top]:
        sport = f":{flow.src_port}" if flow.src_port else ""
        dport = f":{flow.dst_port}" if flow.dst_port else ""
        flow_rows.append(
            [
                flow.proto,
                f"{flow.src}{sport}",
                f"{flow.dst}{dport}",
                str(flow.packets),
                _size(flow.bytes),
                ", ".join(sorted(flow.names)[:3]),
            ]
        )
    name_rows = [[name, str(count)] for name, count in report.names.most_common(top)]
    port_rows = [
        [port_label(port), str(port), str(count)]
        for port, count in report.ports.most_common(top)
    ]
    flag_rows = [[name, str(count)] for name, count in report.flags.most_common(top)]
    status_rows = [[str(status), str(count)] for status, count in report.http_status.most_common(top)]
    icmp_rows = []
    for icmp_type, count in report.icmps.most_common(top):
        icmp_rows.append([str(icmp_type), _icmp_label(icmp_type), str(count)])
    conv_rows = [
        [src, dst, _size(total)] for src, dst, total, _fwd in report.conversations[:top]
    ]
    generated = datetime.now(tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>vacppmp 报告 - {_esc(report.path)}</title>
<style>
:root {{
  --bg: #0d1117;
  --card: #161b22;
  --line: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #58a6ff;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: ui-sans-serif, system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
}}
main {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }}
h1, h2 {{ font-weight: 600; letter-spacing: 0.02em; }}
h1 {{ font-size: 28px; margin: 0 0 8px; }}
h2 {{ font-size: 18px; margin: 36px 0 12px; color: var(--accent); }}
.sub {{ color: var(--muted); margin-bottom: 24px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
.card {{
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 16px;
}}
.card b {{ display: block; font-size: 22px; margin-top: 6px; }}
.map {{
  background: radial-gradient(circle at center, #1b2330 0%, #0d1117 70%);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 8px;
}}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
  word-break: break-all;
}}
th {{ color: var(--muted); font-weight: 600; }}
footer {{ color: var(--muted); margin-top: 40px; font-size: 12px; }}
</style>
</head>
<body>
<main>
  <h1>vacppmp 流量地图</h1>
  <p class="sub">{_esc(report.path)} · {_esc(report.kind)} · 生成于 {_esc(generated)}</p>
  <section class="cards">
    <div class="card">包数<b>{report.packet_count}</b></div>
    <div class="card">字节<b>{_esc(_size(report.byte_count))}</b></div>
    <div class="card">主机<b>{len(report.hosts)}</b></div>
    <div class="card">会话<b>{len(report.conversations)}</b></div>
    <div class="card">时长<b>{report.duration:.3f}s</b></div>
    <div class="card">首包<b>{_esc(_stamp(report.first_ts))}</b></div>
  </section>
  <h2>主机通信图</h2>
  <div class="map">{svg}</div>
  <h2>时间分布</h2>
  <p class="sub">左块：字节；右块：包数；每段约 {report.duration / BUCKETS:.3f} 秒（{BUCKETS} 段）</p>
  <div class="map">{_timeline_svg(report)}</div>
  <h2>传输层</h2>
  {_table(["传输层", "包数", "占比"], tx_rows)}
  <h2>应用协议</h2>
  {_table(["协议", "包数", "占比"], proto_rows)}
  <h2>端口 / 服务</h2>
  {_table(["服务", "端口", "包数"], port_rows) if port_rows else "<p class='sub'>没有 TCP / UDP 端口</p>"}
  <h2>通信对</h2>
  {_table(["源", "目的", "字节"], conv_rows)}
  <h2>主机</h2>
  {_table(["IP", "字节", "包数", "端口", "名字"], host_rows)}
  <h2>流</h2>
  {_table(["协议", "源", "目的", "包数", "字节", "名字"], flow_rows)}
  <h2>TCP 标志位</h2>
  {_table(["标志", "包数"], flag_rows) if flag_rows else "<p class='sub'>没有 TCP 流量</p>"}
  <h2>HTTP 状态码</h2>
  {_table(["状态码", "次数"], status_rows) if status_rows else "<p class='sub'>没有解析到 HTTP 报文</p>"}
  <h2>ICMP</h2>
  {_table(["类型", "含义", "次数"], icmp_rows) if icmp_rows else "<p class='sub'>没有 ICMP 流量</p>"}
  <h2>解析到的名字</h2>
  {_table(["名字", "次数"], name_rows) if name_rows else "<p class='sub'>没有解析到 DNS / HTTP Host / TLS SNI</p>"}
  <footer>vacppmp 离线生成，未上传任何捕获数据。</footer>
</main>
</body>
</html>
"""
