"""Tests for packet layer decoding."""

from tests.factory import (
    dns_query,
    ethernet,
    fragment,
    hop_by_hop,
    http_get,
    http_response,
    icmp_echo,
    ipv4,
    ipv6,
    tcp,
    tls_client_hello,
    udp,
)
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


def test_http_response():
    payload = ethernet(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(80, 4444, http_response(404))))
    frame = decode_frame(payload, 1)
    assert frame.proto == "HTTP"
    assert frame.http_status == 404


def test_http_detected_on_any_port():
    """HTTP on a non-standard port is still recognised by its request line."""
    payload = ethernet(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(4444, 31337, http_get("x.example"))))
    frame = decode_frame(payload, 1)
    assert frame.proto == "HTTP"
    assert frame.http_host == "x.example"


def test_tcp_data_on_unknown_port_stays_tcp():
    payload = ethernet(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(4444, 31337, b"\x01\x02\x03\x04")))
    frame = decode_frame(payload, 1)
    assert frame.proto == "TCP"


def test_ipv6():
    payload = ethernet(ipv6(6, tcp(4444, 80, http_get("v6.example"))), 0x86DD)
    frame = decode_frame(payload, 1)
    assert frame.proto == "HTTP"
    assert frame.ip_version == 6
    assert frame.src_ip == "2001:db8::1"
    assert frame.dst_port == 80


def test_ipv6_fragment():
    inner = tcp(4444, 80, http_get("v6.example"))
    payload = ethernet(ipv6(44, fragment(6, inner)), 0x86DD)
    frame = decode_frame(payload, 1)
    assert frame.proto == "HTTP"
    assert frame.src_port == 4444


def test_ipv6_hop_by_hop_then_fragment():
    inner = tcp(4444, 443, tls_client_hello("v6.example"))
    payload = ethernet(ipv6(0, hop_by_hop(44, fragment(6, inner))), 0x86DD)
    frame = decode_frame(payload, 1)
    assert frame.proto == "TLS"
    assert frame.tls_sni == "v6.example"


def test_ipv6_linktype():
    payload = ipv6(17, udp(53, 53, dns_query("v6.example")))
    frame = decode_frame(payload, 229)
    assert frame.proto == "DNS"
    assert frame.dns_names == ["v6.example"]


def test_icmp_echo_target():
    payload = ethernet(ipv4("10.0.0.1", "10.0.0.8", 1, icmp_echo("10.0.0.8")))
    frame = decode_frame(payload, 1)
    assert frame.proto == "ICMP"
    assert frame.icmp_type == 8
    assert frame.icmp_target == "10.0.0.8"


def test_icmpv6_echo_target():
    inner = ipv6(58, b"")
    echo = bytes([128, 0]) + bytes(6) + inner
    payload = ethernet(ipv6(58, echo), 0x86DD)
    frame = decode_frame(payload, 1)
    assert frame.proto == "ICMPv6"
    assert frame.icmp_target == "2001:db8::2"


def test_tcp_flags():
    payload = ethernet(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(4444, 22, b"")))
    frame = decode_frame(payload, 1)
    assert frame.tcp_flags


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
