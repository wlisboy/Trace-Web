# Trace-Web
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#-开源协议-license)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows-9cf.svg)]()
[![Language](https://img.shields.io/badge/language-Python%20%2B%20Go-00ADD8.svg)]()

## 💡 项目简介

**一个基于 Go 开发的 Cloudflare IP 线路探测与在线优选工具**

![预览](https://images.580609.ccwu.cc/file/Trace-Web/1788157579355_img.webp)

## ✨ 核心特性

- 🔍 **线路探测**：nexttrace-core 式逐跳去程探测，ASN / 运营商 / 所属线路 / 归属地 ，单次上限 300 条
- ⚡ **在线优选**：数据筛选 → 下载测速 → ProxyIP / 风险检测 → 自动排序导出，单次上限 10 万条
- 🕸️ **子网精简**：IPv4 按 `/24`、IPv6 按 `/48` 固定分组，每组仅探测一个代表地址，可大幅缩小候选数量
- 🌐 **Web 控制台**：SSE 实时进度、内置 IP 库导入、历史记录 (可一键重跑)
- 📤 **多端导出**：CSV / TXT 自定义字段，支持 Gist、GitHub 仓库、EdgeTunnel 上传

## 🚀 快速上手

```bash
# 直接运行 CLI 控制台
tracev2.exe -i ip.txt -o result.csv
# 启动 Web 控制台（默认 51917 端口，自动打开浏览器）
trace_webv2.exe --port 8080 --no-browser # 指定 8080端口
```

> **Note**：Web 控制台默认地址为 `http://127.0.0.1:51917/`；端口被占用时会自动改用随机端口，请以启动时打印的地址为准。

## 📖 使用指南

### 目标输入格式

每行一个目标，忽略空行与 `#` 注释，按 host（+端口）自动去重：

```text
1.0.0.1:443              # IPv4（端口可选）
[2606:4700::0]:443       # IPv6
2606:4700::0:443         # 裸 IPv6
example.com:443          # 域名
1.0.0.1/24               # CIDR（仅在线优选）
1.0.0.0-1.0.0.255        # IP 区间（仅在线优选）
```

### CLI 参数说明

| 参数 | 默认值 | 说明 |
| :------ | :------: |:------ |
| `-i` / `--input` | — |导入目标 / IP 文件（*.txt），未指定则交互输入 |
| `-o` / `--output` | `result.csv` |导出结果文件，支持 `.csv` / `.txt` |
| `-u` / `--url` | 关闭 | 下载测速地址，如 `https://example.com/`；开启后默认 `auto` |
| `-s` / `--slim` | 32 | 子网精简并发  workers |
| `-f` / `--filter` | 200 | 数据筛选并发  workers |
| `-d` / `--download` | 5 | 下载测速并发  workers |
| `-r` / `--route` | 15 | 线路探测并发  workers |
| `-mh` / `--max-hops` | 12 | 最大跳数（重试阶段自动放宽至 25） |

> **Note**： 模式专属参数不能混用 `-u` / `-f` / `-d` 只用于在线优选，`-r` / `-mh` 只用于线路探测

### Windows: 普通用户模式（ICMP）需放行防火墙：

```bat
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any

netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## 📄 开源协议

详见 [MIT License](LICENSE) 

## 💖 特别鸣谢

- [nxtrace/NTrace-core](https://github.com/nxtrace/NTrace-core) 
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 
- [PoemMisty/CFData-WEB](https://github.com/PoemMisty/CFData-WEB) 
- [e13815332/ASNIPtest](https://github.com/e13815332/ASNIPtest)
- [Telegram频道/CF_NAT](https://t.me/CF_NAT) 

## ⚠️ 免责声明

1. 本项目（"Trace-Web"）仅供**教育、科学研究及个人安全测试**之目的。
2. 使用者在下载或使用本项目代码时，必须严格遵守所在地区的法律法规。
3. 作者 **wlisboy** 对任何滥用本项目代码导致的行为或后果均不承担任何责任。
4. 本项目不对因使用代码引起的任何直接或间接损害负责。
5. 建议在测试完成后 24 小时内删除本项目相关文件。

------

**如果您觉得项目对您有帮助，请给一个 Star 🌟，这是对我最大的鼓励！**
