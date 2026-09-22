"""Serialize a capture report to JSON for scripting and diffing."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .stats import Report, port_label

__all__ = ["render_json"]


def _iso(ts: float) -> str | None:
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def render_json(report: Report, top: int = 50) -> str:
    """Return an indented JSON document describing the report."""
    data = {
        "file": report.path,
        "format": report.kind,
        "packets": report.packet_count,
        "bytes": report.byte_count,
        "duration_seconds": round(report.duration, 6) if report.ts_known else None,
        "timestamps_known": report.ts_known,
        "first_seen": _iso(report.first_ts),
        "last_seen": _iso(report.last_ts),
        "conversations_count": len(report.conversations),
        "host_count": len(report.hosts),
        "protocols": dict(report.protocols.most_common(top)),
        "transports": dict(report.transports.most_common(top)),
        "ports": {
            str(port): {"service": port_label(port), "packets": count}
            for port, count in report.ports.most_common(top)
        },
        "tcp_flags": dict(report.flags.most_common(top)),
        "http_status": {str(k): v for k, v in report.http_status.most_common(top)},
        "icmp_types": dict(report.icmps.most_common(top)),
        "names": dict(report.names.most_common(top)),
        "tls_sni": dict(report.tls_sni.most_common(top)),
        "http_hosts": dict(report.http_hosts.most_common(top)),
        "conversations": [
            {"src": src, "dst": dst, "bytes": total, "forward_bytes": fwd}
            for src, dst, total, fwd in report.conversations[:top]
        ],
        "hosts": [
            {
                "ip": host.ip,
                "bytes": host.bytes,
                "sent": host.sent,
                "received": host.received,
                "packets": host.packets,
                "ports": sorted(host.ports),
                "names": sorted(host.names),
                "protocols": dict(host.protocols),
            }
            for host in sorted(report.hosts.values(), key=lambda item: item.bytes, reverse=True)[:top]
        ],
        "flows": [
            {
                "proto": flow.proto,
                "src": flow.src,
                "src_port": flow.src_port,
                "dst": flow.dst,
                "dst_port": flow.dst_port,
                "packets": flow.packets,
                "bytes": flow.bytes,
                "names": sorted(flow.names),
                "flags": sorted(flow.flags),
                "first_seen": _iso(flow.ts_first),
                "last_seen": _iso(flow.ts_last),
            }
            for flow in report.flows[:top]
        ],
        "timeline": {
            "buckets": report.timeline,
            "step_seconds": round(report.timeline_step, 6),
        },
    }
    return json.dumps(data, ensure_ascii=False, indent=2)
