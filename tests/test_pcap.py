"""Tests for pcap reading."""

import gzip

import pytest

from tests.factory import (
    dns_query,
    ethernet,
    ipv4,
    ipv6,
    pcap,
    pcap_be,
    pcapng,
    pcapng_multi,
    pcapng_spb,
    tcp,
    udp,
)
from vacppmp.errors import ParseError
from vacppmp.pcap import open_capture


def _dns_frame():
    return ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(53, 53, dns_query("a.test"))))


def test_open_pcap(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "sample.pcap"
    path.write_bytes(pcap([frame, frame]))
    capture = open_capture(path)
    assert capture.kind == "pcap"
    assert capture.linktype == 1
    assert capture.count == 2
    assert capture.packets[0].frame.src_ip == "1.1.1.1"


def test_big_endian_pcap(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "be.pcap"
    path.write_bytes(pcap_be([frame]))
    capture = open_capture(path)
    assert capture.linktype == 1
    assert capture.count == 1
    assert capture.packets[0].ts_sec == 1_700_000_000
    assert capture.packets[0].ts_usec == 500_000
    assert capture.packets[0].frame.src_ip == "1.1.1.1"


def test_big_endian_nanosecond_pcap(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "be_nano.pcap"
    path.write_bytes(pcap_be([frame], nanoseconds=True))
    capture = open_capture(path)
    assert capture.packets[0].ts_sec == 1_700_000_000
    assert capture.packets[0].ts_usec == 500_000


def test_gzip_pcap(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "sample.pcap.gz"
    path.write_bytes(gzip.compress(pcap([frame])))
    capture = open_capture(path)
    assert capture.count == 1


def test_open_pcapng(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "sample.pcapng"
    path.write_bytes(pcapng([frame]))
    capture = open_capture(path)
    assert capture.kind == "pcapng"
    assert capture.linktype == 1
    assert capture.count == 1
    assert capture.packets[0].frame.src_ip == "1.1.1.1"


def test_open_pcapng_tsresol(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "sample_nano.pcapng"
    path.write_bytes(pcapng([frame], tsresol=9))
    capture = open_capture(path)
    assert capture.kind == "pcapng"
    assert capture.count == 1
    assert capture.packets[0].ts_sec == 1_700_000_000
    assert capture.packets[0].ts_usec == 250


def test_spb_has_no_timestamps(tmp_path):
    frame = _dns_frame()
    path = tmp_path / "spb.pcapng"
    path.write_bytes(pcapng_spb([frame]))
    capture = open_capture(path)
    assert capture.count == 1
    assert capture.ts_known is False
    assert capture.packets[0].ts_valid is False


def test_pcapng_multiple_interfaces(tmp_path):
    ether = ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(53, 53, dns_query("a.test"))))
    raw = ipv6(6, tcp(4444, 80, b"GET / HTTP/1.1\r\nHost: v6\r\n\r\n"))
    path = tmp_path / "multi.pcapng"
    path.write_bytes(pcapng_multi(1, [ether], 229, [raw]))
    capture = open_capture(path)
    assert capture.count == 2
    assert capture.packets[0].frame.proto == "DNS"
    assert capture.packets[1].frame.proto == "HTTP"


def test_missing_file(tmp_path):
    with pytest.raises(ParseError, match="找不到"):
        open_capture(tmp_path / "nope.pcap")


def test_bad_magic(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a pcap file at all")
    with pytest.raises(ParseError, match="无法识别"):
        open_capture(path)
