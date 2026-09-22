"""Tests for packet layer decoding."""

from tests.factory import dns_query, ethernet, http_get, ipv4, tcp, tls_client_hello, udp
from vacppmp.decode import decode_frame


def test_udp_dns():
    payload = ethernet(ipv4("1.1.1.1", "8.8.8.8", 17, udp(12345, 53, dns_query("example.com"))))
    frame = decode_frame(payload, 1)
    assert frame.proto == "DNS"
    assert frame.src_ip == "1.1.1.1"
    assert frame.dst_ip == "8.8.8.8"
    assert frame.dst_port == 53
    assert frame.dns_names == ["example.com"]


def test_http():
    payload = ethernet(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(4444, 80, http_get("news.example"))))
    frame = decode_frame(payload, 1)
    assert frame.proto == "HTTP"
    assert frame.http_host == "news.example"
    assert frame.http_method == "GET"


def test_tls_sni():
    payload = ethernet(
        ipv4("10.0.0.5", "93.184.216.34", 6, tcp(52000, 443, tls_client_hello("www.example.com")))
    )
    frame = decode_frame(payload, 1)
    assert frame.proto == "TLS"
    assert frame.tls_sni == "www.example.com"


def test_arp():
    arp = bytes.fromhex("0001080006040001") + bytes.fromhex("aabbccddeeff") + bytes.fromhex(
        "0a000001"
    ) + bytes(6) + bytes.fromhex("0a000002")
    frame = decode_frame(ethernet(arp, 0x0806), 1)
    assert frame.proto == "ARP"
    assert frame.src_ip == "10.0.0.1"
    assert frame.dst_ip == "10.0.0.2"


def test_empty():
    frame = decode_frame(b"", 1)
    assert frame.proto == ""
    assert frame.length == 0
