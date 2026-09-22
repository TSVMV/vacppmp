"""Tests for the vacppmp CLI."""

import pytest

from tests.factory import dns_query, ethernet, ipv4, pcap, udp
from vacppmp.cli import main


def _pcap(tmp_path):
    frame = ethernet(ipv4("10.0.0.2", "8.8.8.8", 17, udp(1234, 53, dns_query("cli.test"))))
    path = tmp_path / "cli.pcap"
    path.write_bytes(pcap([frame]))
    return path


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_info(tmp_path, capsys):
    path = _pcap(tmp_path)
    assert main(["info", str(path)]) == 0
    out = capsys.readouterr().out
    assert "pcap" in out
    assert "包数：1" in out


def test_summary(tmp_path, capsys):
    path = _pcap(tmp_path)
    assert main(["summary", str(path)]) == 0
    out = capsys.readouterr().out
    assert "cli.test" in out
    assert "DNS" in out


def test_html(tmp_path, capsys):
    path = _pcap(tmp_path)
    out_html = tmp_path / "map.html"
    assert main(["html", str(path), "-o", str(out_html)]) == 0
    assert out_html.is_file()
    text = out_html.read_text(encoding="utf-8")
    assert "<svg" in text
    assert "已写出" in capsys.readouterr().out


def test_missing(tmp_path, capsys):
    assert main(["info", str(tmp_path / "no.pcap")]) == 1
    assert "错误" in capsys.readouterr().err
