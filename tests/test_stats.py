"""Tests for aggregation and terminal/html rendering."""

import json

from tests.factory import (
    dns_query,
    ethernet,
    http_get,
    http_response,
    ipv4,
    pcap,
    tcp,
    tls_client_hello,
    udp,
)
from vacppmp.export import render_json
from vacppmp.html import render as render_html
from vacppmp.pcap import open_capture
from vacppmp.stats import build_report, select
from vacppmp.text import render as render_text


def _write(tmp_path):
    frames = [
        ethernet(ipv4("10.0.0.2", "8.8.8.8", 17, udp(1234, 53, dns_query("example.com")))),
        ethernet(ipv4("10.0.0.2", "93.184.216.34", 6, tcp(5555, 80, http_get("example.com")))),
        ethernet(ipv4("10.0.0.2", "1.1.1.1", 17, udp(53, 53, dns_query("one.one.one.one")))),
    ]
    path = tmp_path / "demo.pcap"
    path.write_bytes(pcap(frames))
    return path


def test_report(tmp_path):
    report = build_report(open_capture(_write(tmp_path)))
    assert report.packet_count == 3
    assert "10.0.0.2" in report.hosts
    assert report.protocols["DNS"] >= 1
    assert report.protocols["HTTP"] == 1
    assert "example.com" in report.names
    assert report.conversations


def test_text_and_html(tmp_path):
    report = build_report(open_capture(_write(tmp_path)))
    text = render_text(report)
    assert "应用协议" in text
    assert "传输层" in text
    assert "端口 / 服务" in text
    assert "example.com" in text
    page = render_html(report)
    assert "<svg" in page
    assert "vacppmp" in page
    assert "example.com" in page
    assert "时间分布" in page


def test_one_connection_is_one_flow(tmp_path):
    """TLS handshake then HTTP data on one 4-tuple must stay a single flow."""
    frames = [
        ethernet(ipv4("10.0.0.2", "93.184.216.34", 6, tcp(5555, 443, tls_client_hello("x.test")))),
        ethernet(ipv4("10.0.0.2", "93.184.216.34", 6, tcp(5555, 443, b"\x17\x03\x03\x00\x10hello"))),
    ]
    path = tmp_path / "flow.pcap"
    path.write_bytes(pcap(frames))
    report = build_report(open_capture(path))
    assert len(report.flows) == 1
    assert report.flows[0].packets == 2


def test_http_status_counts(tmp_path):
    frames = [
        ethernet(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 4444, http_response(200)))),
        ethernet(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 4444, http_response(404)))),
    ]
    path = tmp_path / "status.pcap"
    path.write_bytes(pcap(frames))
    report = build_report(open_capture(path))
    assert report.http_status[200] == 1
    assert report.http_status[404] == 1


def test_filter_host(tmp_path):
    capture = open_capture(_write(tmp_path))
    filtered = select(capture, host="8.8.8.8")
    report = build_report(filtered)
    assert report.packet_count == 1
    assert report.protocols["DNS"] == 1


def test_filter_port_and_proto(tmp_path):
    capture = open_capture(_write(tmp_path))
    by_port = build_report(select(capture, port=80))
    assert by_port.packet_count == 1
    assert by_port.protocols["HTTP"] == 1
    by_proto = build_report(select(capture, proto="dns"))
    assert by_proto.packet_count == 2


def test_duration(tmp_path):
    report = build_report(open_capture(_write(tmp_path)))
    assert report.first_ts == 1_700_000_000
    assert report.duration == 2.0


def test_json_export(tmp_path):
    report = build_report(open_capture(_write(tmp_path)))
    data = json.loads(render_json(report))
    assert data["packets"] == 3
    assert data["protocols"]["HTTP"] == 1
    assert data["names"]["example.com"] == 2
    assert data["ports"]["80"]["service"] == "http"
    assert data["timestamps_known"] is True
