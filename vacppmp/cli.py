"""Command line interface for vacppmp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .errors import ParseError, VacppmpError
from .html import render as render_html
from .pcap import open_capture
from .stats import build_report
from .text import render as render_text

__all__ = ["main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vacppmp",
        description="零依赖流量可视化：解析 pcap/pcapng，输出终端摘要和 HTML 通信图",
    )
    parser.add_argument("--version", action="version", version=f"vacppmp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("summary", help="在终端打印协议、主机和会话摘要")
    summary.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    summary.add_argument("--top", type=int, default=12, help="每张表显示的行数")

    html_cmd = sub.add_parser("html", help="生成可截图的 HTML 通信地图")
    html_cmd.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    html_cmd.add_argument("-o", "--output", default="", help="输出 HTML 路径，默认 <文件名>.html")
    html_cmd.add_argument("--top", type=int, default=20, help="表格行数")

    report = sub.add_parser("report", help="同时打印摘要并写出 HTML")
    report.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    report.add_argument("-o", "--output", default="", help="输出 HTML 路径，默认 <文件名>.html")
    report.add_argument("--top", type=int, default=12, help="终端摘要行数")

    info = sub.add_parser("info", help="只显示文件格式与包数")
    info.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    return parser


def _html_path(pcap: str, output: str) -> Path:
    if output:
        return Path(output)
    return Path(pcap).with_suffix(".html")


def _load(path: str):
    return build_report(open_capture(path))


def cmd_summary(args: argparse.Namespace) -> int:
    print(render_text(_load(args.pcap), top=args.top), end="")
    return 0


def cmd_html(args: argparse.Namespace) -> int:
    report = _load(args.pcap)
    target = _html_path(args.pcap, args.output)
    target.write_text(render_html(report, top=args.top), encoding="utf-8")
    print(f"已写出 {target}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = _load(args.pcap)
    print(render_text(report, top=args.top), end="")
    target = _html_path(args.pcap, args.output)
    target.write_text(render_html(report, top=max(args.top, 20)), encoding="utf-8")
    print(f"已写出 {target}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    capture = open_capture(args.pcap)
    print(f"文件：{capture.path}")
    print(f"格式：{capture.kind}")
    print(f"链路类型：{capture.linktype}")
    print(f"包数：{capture.count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "summary": cmd_summary,
        "html": cmd_html,
        "report": cmd_report,
        "info": cmd_info,
    }
    try:
        return handlers[args.command](args)
    except (VacppmpError, ParseError, OSError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
