# vacppmp

零依赖流量可视化：读 pcap / pcapng，在终端打摘要，再画出可截图的主机通信图。

蓝队向。只解析本地捕获文件，不发包、不扫描、不上网。

## 安装

```bash
pip install vacppmp
```

## 快速开始

```bash
vacppmp summary capture.pcap
vacppmp html capture.pcap -o map.html
vacppmp report capture.pcap
```

`report` 会先打印终端摘要，再写出同名 HTML。

## 子命令

| 命令 | 说明 |
| --- | --- |
| `vacppmp info <文件>` | 格式、链路类型、包数 |
| `vacppmp summary <文件>` | 协议分布、通信对、DNS/HTTP/TLS 名字、流 |
| `vacppmp html <文件> [-o 出.html]` | 生成深色 HTML 通信地图 |
| `vacppmp report <文件>` | 摘要 + HTML |

## 能看清什么

- Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP
- Linux cooked capture（SLL / SLL2）
- 按端口识别 SSH、DNS、HTTP、TLS、SMB 等常见服务
- DNS 查询名、HTTP Host、TLS SNI
- 主机气泡图：点是 IP（有名字就显示名字），线粗细代表字节量

## 开发

```bash
pip install -e ".[test]"
pytest tests/
ruff check .
```

## 许可证

MIT
