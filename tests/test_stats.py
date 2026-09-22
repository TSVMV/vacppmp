"""Tests for aggregation and terminal/html rendering."""

from tests.factory import dns_query, ethernet, http_get, ipv4, pcap, tcp, udp
from vacppmp.html import render as render_html
from vacppmp.pcap import open_capture
from vacppmp.stats import build_report
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
    assert "协议分布" in text
    assert "example.com" in text
    page = render_html(report)
    assert "<svg" in page
    assert "vacppmp" in page
    assert "example.com" in page
