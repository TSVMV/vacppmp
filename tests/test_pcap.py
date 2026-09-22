"""Tests for pcap reading."""

import pytest

from tests.factory import dns_query, ethernet, ipv4, pcap, pcapng, udp
from vacppmp.errors import ParseError
from vacppmp.pcap import open_capture


def test_open_pcap(tmp_path):
    frame = ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(53, 53, dns_query("a.test"))))
    path = tmp_path / "sample.pcap"
    path.write_bytes(pcap([frame, frame]))
    capture = open_capture(path)
    assert capture.kind == "pcap"
    assert capture.linktype == 1
    assert capture.count == 2
    assert capture.packets[0].frame.src_ip == "1.1.1.1"


def test_open_pcapng(tmp_path):
    frame = ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(53, 53, dns_query("a.test"))))
    path = tmp_path / "sample.pcapng"
    path.write_bytes(pcapng([frame]))
    capture = open_capture(path)
    assert capture.kind == "pcapng"
    assert capture.linktype == 1
    assert capture.count == 1
    assert capture.packets[0].frame.src_ip == "1.1.1.1"


def test_open_pcapng_tsresol(tmp_path):
    frame = ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(53, 53, dns_query("a.test"))))
    path = tmp_path / "sample_nano.pcapng"
    path.write_bytes(pcapng([frame], tsresol=9))
    capture = open_capture(path)
    assert capture.kind == "pcapng"
    assert capture.count == 1
    assert capture.packets[0].ts_sec > 1_700_000_000


def test_missing_file(tmp_path):
    with pytest.raises(ParseError, match="找不到"):
        open_capture(tmp_path / "nope.pcap")


def test_bad_magic(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a pcap file at all")
    with pytest.raises(ParseError, match="无法识别"):
        open_capture(path)
