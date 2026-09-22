"""Command line interface for vacppmp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .errors import ParseError, VacppmpError
from .export import render_json
from .html import render as render_html
from .pcap import open_capture
from .stats import build_report, select
from .text import render as render_text

__all__ = ["main"]

FILTERS = ("--host", "--port", "--proto")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vacppmp",
        description="零依赖流量可视化：解析 pcap/pcapng，输出终端摘要、HTML 通信图和 JSON",
    )
    parser.add_argument("--version", action="version", version=f"vacppmp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("summary", help="在终端打印协议、主机和会话摘要")
    summary.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    summary.add_argument("--top", type=int, default=12, help="每张表显示的行数")
    _add_filters(summary)

    html_cmd = sub.add_parser("html", help="生成可截图的 HTML 通信地图")
    html_cmd.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    html_cmd.add_argument("-o", "--output", default="", help="输出 HTML 路径，默认 <文件名>.html")
    html_cmd.add_argument("--top", type=int, default=20, help="表格行数")
    _add_filters(html_cmd)

    json_cmd = sub.add_parser("json", help="导出机器可读的 JSON 报告")
    json_cmd.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    json_cmd.add_argument("-o", "--output", default="", help="输出 JSON 路径，缺省打印到终端")
    json_cmd.add_argument("--top", type=int, default=50, help="每张表的条数上限")
    _add_filters(json_cmd)

    report = sub.add_parser("report", help="打印摘要并写出 HTML 与 JSON")
    report.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    report.add_argument("-o", "--output", default="", help="输出目录或文件前缀，缺省用捕获文件名")
    report.add_argument("--top", type=int, default=12, help="终端摘要行数")
    _add_filters(report)

    info = sub.add_parser("info", help="只显示文件格式、链路类型和包数")
    info.add_argument("pcap", help="pcap 或 pcapng 文件路径")
    return parser


def _add_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="", help="只看涉及该 IP 的包")
    parser.add_argument("--port", type=int, default=0, help="只看涉及该端口的包")
    parser.add_argument("--proto", default="", help="只看该协议，如 TCP UDP DNS HTTP TLS ARP")


def _html_path(pcap: str, output: str) -> Path:
    if output:
        return Path(output)
    return Path(pcap).with_suffix(".html")


def _json_path(pcap: str, output: str) -> Path:
    if output:
        return Path(output)
    return Path(pcap).with_suffix(".json")


def _report(args: argparse.Namespace, pcap: str):
    capture = open_capture(pcap)
    capture = select(capture, host=args.host, port=args.port, proto=args.proto)
    return build_report(capture)


def cmd_summary(args: argparse.Namespace) -> int:
    print(render_text(_report(args, args.pcap), top=args.top), end="")
    return 0


def cmd_html(args: argparse.Namespace) -> int:
    target = _html_path(args.pcap, args.output)
    target.write_text(render_html(_report(args, args.pcap), top=args.top), encoding="utf-8")
    print(f"已写出 {target}")
    return 0


def cmd_json(args: argparse.Namespace) -> int:
    payload = render_json(_report(args, args.pcap), top=args.top)
    target = _json_path(args.pcap, args.output)
    if args.output:
        target.write_text(payload + "\n", encoding="utf-8")
        print(f"已写出 {target}")
    else:
        print(payload)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = _report(args, args.pcap)
    print(render_text(report, top=args.top), end="")
    target = _html_path(args.pcap, args.output)
    target.write_text(render_html(report, top=max(args.top, 20)), encoding="utf-8")
    json_target = _json_path(args.pcap, args.output)
    json_target.write_text(render_json(report, top=max(args.top, 50)) + "\n", encoding="utf-8")
    print(f"已写出 {target}")
    print(f"已写出 {json_target}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    capture = open_capture(args.pcap)
    undecoded = sum(1 for packet in capture.packets if not packet.frame.proto)
    print(f"文件：{capture.path}")
    print(f"格式：{capture.kind}")
    print(f"链路类型：{capture.linktype}")
    print(f"包数：{capture.count}")
    print(f"未识别：{undecoded}")
    print(f"时间戳：{'有' if capture.ts_known else '无（无法计算时长）'}")
    if capture.interfaces:
        print(f"接口：{len(capture.interfaces)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "summary": cmd_summary,
        "html": cmd_html,
        "json": cmd_json,
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
