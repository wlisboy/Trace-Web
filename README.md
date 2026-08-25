# Trace-Web
Trace-Web 是一个基于 Go 开发的 Cloudflare IP 线路匹配与在线优选工具

<img src="img.png">

## 运行参数

| 参数 | 默认值 | 说明 |
| :------ | :------: | :------|
| `-f`/ `--file` | — | 导入测试目标/IP 的文件（*.txt） |
| `-o`/ `--output` | `result.csv` | 导出结果的 CSV 文件） |
| `-u`/ `--url` | 关闭 | 下载测速地址 |
| `-n`/ `--num` | `200` | 数据筛选并发 workers |
| `-d`/ `--download` | `5` | 下载测速并发 workers |
| `-w`/ `--worker` | `15` | 线路匹配并发 workers |
| `-mh`/ `--max-hops` | `12` | 最大跳数（失败重试阶段自动放宽至 25） |
| `-me`/ `--max-empty` | `8` | 连续无响应跳数上限（重试阶段自动放宽至 12） |
| `-th`/ `--timeout-hop` | `500` | 单跳超时毫秒（重试阶段自动放宽至 1000） |
| `-tt`/ `--timeout-total` | `60000` | 单目标总超时毫秒（重试阶段自动放宽至 90000） |

## 线路识别
| ASN | 运营商| 所属线路 |
| :------: | :------: | :------: |
| AS2914 | 日本电信 | NTT |
| AS4134 | 中国电信 | 163骨干 |
| AS4812 | 中国电信 | CN2 |
| AS4809 | 中国电信 | CN2 GIA/GT |
| AS4837 | 中国联通 | 169骨干 |
| AS9929 | 中国联通 | CUII (A网) |
| AS9808 | 中国移动 | CMNET |
| AS58453 | 中国移动 | CMI |
| AS58807 | 中国移动 | CMIN2 |
| AS4538 | 中国教育网 | CERNET |
| AS7497 | 中国科技网 | CSTNET |

## 注意事项

`Windows` 用户必须完成的配置步骤

- 对于普通用户模式 (ICMP mode, 且需防火墙配置允许ICMP/ICMP)

```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any

netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

- 线路匹配 
 
 单次上限 **65536** 个地址

- 在线优选
 
 单次上限 **100000** 个地址

## 项目结构

```
├── tracev2.exe              # CLI 
├── trace_webv2.exe          # Web 端
└── data/
    ├── asn_prefixes.json      # RIPEStat → 线路识别
    ├── locations.json         # 白嫖哥 → Cloudflare 数据中心位置
    └── GeoLite2-ASN.mmdb      # MaxMind → ASN 数据库
```

## 项目参考（以下排名不分先后）
- [nxtrace/NTrace-core](https://github.com/nxtrace/NTrace-core)
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)
- [PoemMisty/CFData-WEB](https://github.com/PoemMisty/CFData-WEB)
- [e13815332/ASNIPtest](https://github.com/e13815332/ASNIPtest)

## 许可证
详见 [LICENSE](LICENSE)
