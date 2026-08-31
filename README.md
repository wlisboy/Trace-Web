# Trace-Web
Trace-Web 是一个基于 Go 开发的 Cloudflare IP 线路探测与在线优选工具

![img.png](https://images.580609.ccwu.cc/file/Trace-Web/1788157579355_img.webp)

## CLI 参数说明

| 参数 | 默认值 | 说明 |
| :------ | :------: | :------|
| `-i` / `--input` | — | 导入测试目标/IP 的文件（*.txt） |
| `-o` / `--output` | `result.csv` | 导出结果的 CSV 文件） |
| `-u` / `--url` | 关闭 | 下载测速地址 |
| `-s` / `--slim` | `32`| 子网精简并发 workers |
| `-f` / `--filter` | `200` | 数据筛选并发 workers |
| `-d` / `--download` | `5` | 下载测速并发 workers |
| `-r` / `--route` | `15` | 线路匹配并发 workers |
| `-mh` / `--max-hops` | `12` | 最大跳数（失败重试阶段自动放宽至 25） |

## Web 界面部分功能说明

`子网精简` 
- IPv4 地址固定按 `/24` 分组，IPv6 地址固定按 `/48` 分组,
- 每个分组只选取一个代表地址做探测、可用时保留整组，不可用时淘汰整组

`筛选`
- 文本列 (除丢包率、网络延迟、下载速度列)
  - 直接搜关键字（模糊匹配），多个词用逗号隔开表示“或
  - `!` = 排除
  - `=` = 精确匹配

- 数字列 (丢包率、网络延迟、下载速度列)
  - 运算符号查询: >|<|>=|<=|=|+数字，例如: >10 | <20 | >=10 | <=20 | =10 | =20
  - 区间查询: 10-20 等价于 10<=x<=20

## 注意事项

`Windows` 用户必须完成的配置步骤

- 对于普通用户模式 (ICMP mode, 且需防火墙配置允许ICMP/ICMP)

```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any

netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

- 线路匹配 
 
 单次上限 **100** 个地址

- 在线优选
 
 单次上限 **100000** 个地址

## 项目结构

```
├── tracev2.exe              # CLI 
├── trace_webv2.exe          # Web
└── data/
    ├── locations.json         # 白嫖哥 → Cloudflare 数据中心位置
    └── GeoLite2-ASN.mmdb      # MaxMind → ASN 数据库
```

## 项目参考（以下排名不分先后）
- [nxtrace/NTrace-core](https://github.com/nxtrace/NTrace-core)
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)
- [PoemMisty/CFData-WEB](https://github.com/PoemMisty/CFData-WEB)
- [e13815332/ASNIPtest](https://github.com/e13815332/ASNIPtest)
- [Telegram频道/CF_NAT](https://t.me/CF_NAT)

## 许可证
详见 [LICENSE](LICENSE)
