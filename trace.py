# MIT License
#
# Copyright (c) 2026 wlisboy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
trace - 线路探测 / 在线优选 示例（CLI + Web）

架构：核心逻辑一份，双前端共用

        [CLI 终端] ──┐
                     ├─► 同一套核心逻辑 ─► [Go 后端 main.exe] ─► JSON Lines 事件流
        [Web 控制台]─┘

设计要点
--------
1. 前后端分离
   前端只负责交互与展示；网络探测、测速、IP 库查询全部由后端完成，
   前端通过子进程调用后端

2. 事件流驱动
   后端把进度与结果以 JSON Lines 格式逐行写到 stdout，前端逐行消费。
   这让「终端进度渲染」与「Web SSE 实时推送」共用同一份消费代码

3. 单一职责
   目标解析 / 命令构建 / 事件消费 / 结果导出 各自是独立的纯函数，
   便于阅读、测试与复用。

运行
----
    py scripts/trace.py -t line -i ip.txt -o result.csv   # 线路探测
    py scripts/trace.py -t optimize -i ip.txt             # 在线优选
    py scripts/trace.py -m web                            # Web

后端事件类型（JSON Lines）
-------------------------
    result        线路探测单条结果
    trace_summary 线路探测汇总
    opt_record    在线优选单条结果
    opt_stage     在线优选阶段切换
    job_done      任务结束
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

__version__ = "1.0.0"


def _force_utf8() -> None:
    """Windows 控制台与标准流统一 UTF-8，避免中文乱码。"""
    os.environ.setdefault("PYTHONUTF8", "1")
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_force_utf8()

# ---------------------------------------------------------------------------
# 常量与后端定位
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"          # 后端运行所需的数据库目录

DEFAULT_WORKER = 15          # 线路探测并发
DEFAULT_MAX_HOPS = 12        # 线路探测最大跳数
DEFAULT_FILTER_WORKERS = 200 # 在线优选筛选并发
DEFAULT_DOWNLOAD_WORKERS = 5 # 在线优选下载测速并发
DEFAULT_URL = "auto"         # 下载测速地址
DISPLAY_COUNT = 10           # 结果展示条数
MAX_TARGETS = {"line": 100, "optimize": 100000}

TRACE_HEADERS = ["IP地址", "ASN", "所属线路", "主机名", "运营商", "状态"]
OPTIMIZE_HEADERS = [
    "IP地址", "端口号", "TLS", "HTTP", "丢包率", "网络延迟", "下载速度",
    "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市",
    "ASN号码", "ASN组织", "ProxyIP", "风险等级",
]


def _find_main_exe() -> str:
    """在常见位置查找后端 main.exe（开发态）。"""
    for candidate in (PROJECT_ROOT / "main.exe",
                      PROJECT_ROOT / "dist" / "main.exe",
                      PROJECT_ROOT / "backend" / "main.exe"):
        if candidate.is_file():
            return str(candidate)
    return str(PROJECT_ROOT / "main.exe")


MAIN_EXE = _find_main_exe()


def verify_backend() -> None:
    """启动前检查后端是否存在，缺失时给出构建提示。"""
    if not os.path.isfile(MAIN_EXE):
        print("[-] 未找到 main.exe，请先构建后端: "
              "cd backend && go build -o ..\\dist\\main.exe .", file=sys.stderr)
        sys.exit(1)
# ---------------------------------------------------------------------------
# 目标解析
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _extract_token(line: str, line_number: int) -> str | None:
    """从一行输入中提取目标 token。

    - '#' 后视为注释，空行返回 None；
    - 校验显式端口（1-65535）与字面 IPv4；
    - 域名 / IPv6 / CIDR / IP 区间等其余格式交给后端解析。
    """
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    if re.search(r"\s", content):
        raise ValueError(f"第 {line_number} 行包含空白，每行只能有一个目标: '{content}'")

    host, port = content, ""
    if content.startswith("["):
        host = content[1:content.find("]")]
        port = content[content.find("]") + 1:].lstrip(":")
    elif content.count(":") == 1:
        host, _, port = content.rpartition(":")
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise ValueError(f"第 {line_number} 行端口必须为 1-65535: '{content}'")
    if "." in host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if _IPV4_RE.fullmatch(host):
                raise ValueError(f"第 {line_number} 行不是有效 IPv4: '{content}'")
    return content


def read_targets(path: str) -> list[str]:
    """读取目标列表：每行一个 IP/域名[:端口]、CIDR 或 IP 区间。"""
    tokens: list[str] = []
    try:
        with open(path, encoding="utf-8-sig", errors="ignore") as fh:
            for line_number, raw in enumerate(fh, 1):
                token = _extract_token(raw, line_number)
                if token:
                    tokens.append(token)
    except OSError as exc:
        raise RuntimeError(f"无法读取文件 '{path}': {exc}") from exc
    return tokens


# ---------------------------------------------------------------------------
# 后端命令构建
# ---------------------------------------------------------------------------


def build_match_cmd(input_file: str, worker: int, max_hops: int) -> list[str]:
    """线路探测命令：main.exe -nexttrace（nexttrace-core 式探测）。"""
    return [MAIN_EXE, "-nexttrace", "-i", input_file, "-input-json=true",
            "-r", str(worker), "-max-hops", str(max_hops)]


def build_optimize_cmd(input_file: str, payload: dict) -> list[str]:
    """在线优选命令：main.exe -optimize-probe（筛选 -> 测速 -> 整理）。"""
    cmd = [MAIN_EXE, "-optimize-probe", "-i", input_file, "-input-json=true",
           "-f", str(payload.get("filter_workers", DEFAULT_FILTER_WORKERS)),
           "-download-workers", str(payload.get("download_workers", DEFAULT_DOWNLOAD_WORKERS)),
           "-latency-min", str(payload.get("latency_min", 0)),
           "-latency-max", str(payload.get("latency_max", 999))]
    if payload.get("download_speed"):
        cmd += ["-url", str(payload.get("url") or DEFAULT_URL)]
    return cmd


@contextlib.contextmanager
def _input_file(entries: list[str]):
    """把目标写入临时输入文件，供后端读取；离开上下文时自动清理。"""
    fd, path = tempfile.mkstemp(prefix="trace_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps({"token": entry}, ensure_ascii=False) + "\n")
    try:
        yield path
    finally:
        os.unlink(path)
# ---------------------------------------------------------------------------
# 事件流：本示例的核心抽象
# ---------------------------------------------------------------------------


def _decode(raw: bytes) -> str:
    """解码后端输出：优先 UTF-8，兜底 gb18030（旧版 Windows 控制台）。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gb18030", errors="replace")


def iter_events(cmd: list[str]):
    """启动后端子进程，逐行产出 JSON 事件（生成器）。

    这是前后端之间的"唯一通道"：CLI 逐条打印、Web 用 SSE 推给浏览器，
    两者只是消费方式不同，事件处理逻辑完全共用。

    - 后端约定：结果与进度以 JSON Lines 输出到 stdout；
    - 非 JSON 行按 ``{"type": "log"}`` 透传，方便前端展示；
    - stderr 由后台线程排空，防止管道写满导致后端阻塞。
    """
    env = os.environ.copy()
    env["TRACE_DATA_DIR"] = str(DATA_DIR)
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    stderr_lines: list[str] = []

    def drain_stderr() -> None:
        for raw in proc.stderr:
            stderr_lines.append(_decode(raw))

    threading.Thread(target=drain_stderr, daemon=True).start()
    try:
        for raw in proc.stdout:
            line = _decode(raw).strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                yield {"type": "log", "message": line}
    finally:
        ret = proc.wait()
        for stream in (proc.stdout, proc.stderr):
            stream.close()
        if ret != 0:
            detail = "".join(stderr_lines).strip()
            raise RuntimeError(f"main.exe 异常退出 (code={ret}): {detail[:200]}")


# ---------------------------------------------------------------------------
# 结果整理
# ---------------------------------------------------------------------------


def display_ip(value: object) -> str:
    """IPv6 用方括号包裹展示（如 [2606:4700::1]）。"""
    text = str(value or "")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    return f"[{text}]" if address.version == 6 else text


def normalize_result(event: dict) -> list[str]:
    """把后端 result 事件整理为表格行：[IP, ASN, 线路, 主机名, 运营商, 状态]。"""
    def field(key: str) -> str:
        value = str(event.get(key) or "").strip()
        return "error" if not value or value.lower() == "none" else value

    fields = [field("matched_asn"), field("line_type"),
              field("hostname"), field("isp")]
    status = "失败" if event.get("error") or "error" in fields else "成功"
    return [display_ip(event.get("target", "")), *fields, status]


# ---------------------------------------------------------------------------
# CSV 导出
# ---------------------------------------------------------------------------


class AtomicCsvWriter:
    """先写临时文件再原子替换：避免导出中断留下半个文件。"""

    def __init__(self, output_path: str, headers: list[str], delimiter: str = ","):
        target = os.path.abspath(output_path)
        output_dir = os.path.dirname(target) or os.curdir
        fd, self._tmp = tempfile.mkstemp(prefix=".trace_", suffix=".tmp", dir=output_dir)
        self._fh = os.fdopen(fd, "w", newline="", encoding="utf-8-sig")
        self._writer = csv.writer(self._fh, delimiter=delimiter)
        self._writer.writerow(headers)
        self._target = target

    def write_row(self, row) -> None:
        self._writer.writerow(row)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._fh.close()
            if exc_type is None:
                os.replace(self._tmp, self._target)
            else:
                os.remove(self._tmp)
        except OSError:
            try:
                os.remove(self._tmp)
            except OSError:
                pass
            raise
        return False


def export_csv_text(headers: list[str], rows: list[list], delimiter: str = ",") -> str:
    """把表格转为 CSV 文本（Web 导出用）。"""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter)
    writer.writerow(headers)
    writer.writerows(rows)
    return buffer.getvalue()


def write_csv(rows: list[list], headers: list[str], output_path: str) -> None:
    """写出结果文件：.txt 用制表符（TSV），其余用逗号（CSV）。"""
    delimiter = "\t" if output_path.lower().endswith(".txt") else ","
    with AtomicCsvWriter(output_path, headers, delimiter) as writer:
        for row in rows:
            writer.write_row(row)
    print(f"[+] 已导出 {len(rows)} 行 -> {output_path}")
# ---------------------------------------------------------------------------
# CLI 前端
# ---------------------------------------------------------------------------


def run_match(entries: list[str], worker: int, max_hops: int) -> list[list]:
    """线路探测：写输入 -> 读事件流 -> 收集结果行。"""
    total = len(entries)
    rows: list[list] = []
    with _input_file(entries) as path:
        for ev in iter_events(build_match_cmd(path, worker, max_hops)):
            if ev.get("type") == "result":
                rows.append(normalize_result(ev))
                print(f"\r[线路探测] 完成 {len(rows)}/{total}", end="", flush=True)
    print()
    return rows


def run_optimize(entries: list[str], payload: dict) -> list[list]:
    """在线优选：写输入 -> 读事件流 -> 收集合格结果行。"""
    rows: list[list] = []
    with _input_file(entries) as path:
        for ev in iter_events(build_optimize_cmd(path, payload)):
            if ev.get("type") == "opt_stage":
                print(f"[优选] 阶段 {ev.get('phase')}: {ev.get('status')}")
            elif ev.get("type") == "opt_record":
                record = ev.get("record") or {}
                if ev.get("display", True) and record.get("qualified"):
                    rows.append(list(ev.get("row") or []))
    return rows


def show_top(headers: list[str], rows: list[list], limit: int = DISPLAY_COUNT) -> None:
    """在终端展示前 limit 条结果（后端已完成排序）。"""
    print("-" * 60)
    print(f"[+] 结果 TOP{min(limit, len(rows))}:")
    for row in rows[:limit]:
        print("  ".join(str(cell) for cell in row))


def cli_main(args) -> None:
    """CLI 入口：解析参数 -> 读取目标 -> 执行任务 -> 导出结果。"""
    verify_backend()
    if not args.input:
        print("[-] 缺少输入文件，请使用 -i 指定目标文件", file=sys.stderr)
        sys.exit(1)
    try:
        entries = read_targets(args.input)
    except (RuntimeError, ValueError) as exc:
        print(f"[-] 错误: {exc}", file=sys.stderr)
        sys.exit(1)
    if not entries:
        print("[-] 输入文件中没有有效目标", file=sys.stderr)
        sys.exit(1)
    if len(entries) > MAX_TARGETS[args.task]:
        print(f"[-] 目标数量超出限制 ({MAX_TARGETS[args.task]})", file=sys.stderr)
        sys.exit(1)
    print(f"[+] 已读取目标: {len(entries)} 条")

    output = args.output or ("result.csv" if args.task == "line" else "result_optimize.csv")
    try:
        if args.task == "line":
            rows = run_match(entries, args.worker or DEFAULT_WORKER,
                             args.max_hops or DEFAULT_MAX_HOPS)
            show_top(TRACE_HEADERS, rows)
            write_csv(rows, TRACE_HEADERS, output)
        else:
            payload = {
                "filter_workers": args.filter_workers or DEFAULT_FILTER_WORKERS,
                "download_workers": args.download_workers or DEFAULT_DOWNLOAD_WORKERS,
                "latency_min": args.latency_min,
                "latency_max": args.latency_max,
                "download_speed": args.download_speed,
                "url": args.url or DEFAULT_URL,
            }
            rows = run_optimize(entries, payload)
            show_top(OPTIMIZE_HEADERS, rows)
            write_csv(rows, OPTIMIZE_HEADERS, output)
    except RuntimeError as exc:
        print(f"[-] 错误: {exc}", file=sys.stderr)
        sys.exit(1)
# ---------------------------------------------------------------------------
# Web 前端：任务管理与 SSE 推送
# ---------------------------------------------------------------------------

JOBS: dict[str, dict] = {}     # 内存任务表: job_id -> {events, rows, meta}
JOBS_LOCK = threading.Lock()


def launch_job(payload: dict) -> str:
    """创建任务并启动后台线程消费事件流，立即返回 job_id。"""
    job_id = os.urandom(8).hex()
    with JOBS_LOCK:
        JOBS[job_id] = {
            "events": [],   # 事件流（SSE 用）
            "rows": [],     # 结果行（详情/导出用）
            "meta": {"mode": payload.get("mode", "line"),
                     "status": "running",
                     "created": time.time(),
                     "result_count": 0,
                     "target_count": len(payload.get("targets", []))},
        }
    threading.Thread(target=_consume_job, args=(job_id, payload), daemon=True).start()
    return job_id


def _consume_job(job_id: str, payload: dict) -> None:
    """后台线程：与 CLI 共用 iter_events，把事件写入任务表。"""
    job = JOBS[job_id]
    error, message = False, None
    try:
        mode = payload.get("mode", "line")
        with _input_file(payload["targets"]) as path:
            cmd = (build_match_cmd(path, payload.get("worker", DEFAULT_WORKER),
                                   payload.get("max_hops", DEFAULT_MAX_HOPS))
                   if mode == "line" else build_optimize_cmd(path, payload))
            for ev in iter_events(cmd):
                with JOBS_LOCK:
                    job["events"].append(ev)
                    if ev.get("type") == "result" and mode == "line":
                        row = normalize_result(ev)
                        job["rows"].append(row)
                        if row[-1] == "成功":
                            job["meta"]["result_count"] += 1
                    elif ev.get("type") == "opt_record" and mode == "optimize":
                        if ev.get("display", True) and (ev.get("record") or {}).get("qualified"):
                            job["rows"].append(list(ev.get("row") or []))
                            job["meta"]["result_count"] += 1
    except Exception as exc:            # 捕获后任务标记失败，事件流照常结束
        error, message = True, str(exc)
    with JOBS_LOCK:
        job["meta"]["status"] = "failed" if error else "done"
        job["events"].append({"type": "job_done", "error": error, "message": message})


def _job_summary(job_id: str, job: dict) -> dict:
    meta = job["meta"]
    return {"id": job_id, "mode": meta["mode"], "status": meta["status"],
            "result_count": meta["result_count"], "target_count": meta["target_count"],
            "created_text": time.strftime("%m-%d %H:%M",
                                          time.localtime(meta["created"]))}


def _job_detail(job_id: str, job: dict) -> dict:
    headers = TRACE_HEADERS if job["meta"]["mode"] == "line" else OPTIMIZE_HEADERS
    return {"id": job_id, "headers": headers, "rows": job["rows"][:500],
            **_job_summary(job_id, job)}


# ---------------------------------------------------------------------------
# Web 前端：HTTP 服务
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, value, status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send_html(PAGE_HTML)
        elif path == "/api/jobs":
            with JOBS_LOCK:
                jobs = [_job_summary(job_id, job) for job_id, job in JOBS.items()]
            self.send_json({"jobs": jobs})
        elif path.startswith("/api/jobs/"):
            parts = path.split("/")          # ['', 'api', 'jobs', <id>, ...]
            with JOBS_LOCK:
                job = JOBS.get(parts[3])
            if job is None:
                self.send_json({"error": "任务不存在"}, 404)
            elif len(parts) == 4:
                self.send_json(_job_detail(parts[3], job))
            elif parts[4] == "events":
                self._send_events(parts[3], job)
            elif parts[4] == "export":
                self._send_export(parts[3], job)
            else:
                self.send_json({"error": "未找到"}, 404)
        else:
            self.send_json({"error": "未找到"}, 404)

    def _send_html(self, html: str) -> None:
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_events(self, job_id: str, job: dict) -> None:
        """SSE 长连接：把任务事件实时推送给浏览器，job_done 后结束。"""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        sent = 0
        try:
            while True:
                with JOBS_LOCK:
                    batch = job["events"][sent:]
                for event in batch:
                    self.wfile.write(
                        ("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode())
                    sent += 1
                if batch:
                    self.wfile.flush()
                    if batch[-1].get("type") == "job_done":
                        break
                time.sleep(0.2)
        except OSError:                     # 浏览器断开连接
            return

    def _send_export(self, job_id: str, job: dict) -> None:
        headers = TRACE_HEADERS if job["meta"]["mode"] == "line" else OPTIMIZE_HEADERS
        with JOBS_LOCK:
            rows = list(job["rows"])
        data = ("\ufeff" + export_csv_text(headers, rows)).encode()   # BOM 兼容 Excel
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{job_id}.csv"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/api/jobs":
            self.send_json({"error": "未找到"}, 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1 << 20:
            self.send_json({"error": "请求体过大或为空"}, 400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_json({"error": "无效的 JSON 请求体"}, 400)
            return
        mode = payload.get("mode", "line")
        targets = payload.get("targets")
        if mode not in ("line", "optimize") or not isinstance(targets, list) or not targets:
            self.send_json({"error": "参数无效: 需要 mode 与 targets"}, 400)
            return
        targets = [str(target).strip() for target in targets if str(target).strip()]
        if not targets or len(targets) > MAX_TARGETS[mode]:
            self.send_json({"error": f"目标数量超出限制 ({MAX_TARGETS[mode]})"}, 400)
            return
        payload["targets"] = targets
        self.send_json({"id": launch_job(payload), "ok": True})

    def log_message(self, *args):
        pass    # 关闭默认请求日志


def web_main(args) -> None:
    verify_backend()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if not args.no_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trace（线路探测 / 在线优选）</title>
<style>
body{font:14px/1.6 system-ui,"PingFang SC","Microsoft YaHei",sans-serif;margin:24px;color:#222;background:#f6f7f9}
h2{margin:0 0 12px}
.panel{border:1px solid #dcdde1;border-radius:8px;padding:16px;margin-bottom:16px;background:#fff}
label{font-size:12px;color:#666}
textarea{width:100%;min-height:110px;font-family:Consolas,monospace}
.row{display:flex;gap:10px;margin:8px 0;align-items:center;flex-wrap:wrap}
.row input[type=number]{width:110px}
button{padding:6px 14px;cursor:pointer}
#status{color:#888}
#events{height:150px;overflow:auto;border:1px solid #ddd;border-radius:6px;padding:8px;background:#fdfdfe;font:12px/1.5 Consolas,monospace;white-space:pre-wrap}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #e3e3e6;padding:5px 8px;text-align:left;white-space:nowrap}
th{background:#f2f3f5}
#jobs div{padding:4px 0;cursor:pointer;border-bottom:1px solid #eee}
#jobs div:hover{background:#f0f1f4}
</style>
</head>
<body>
<h2>Trace（线路探测 / 在线优选）</h2>
<div class="panel">
  <div class="row">
    <select id="mode"><option value="line">线路探测</option><option value="optimize">在线优选</option></select>
    <input id="worker" type="number" value="15" title="并发">
    <input id="max_hops" type="number" value="12" title="最大跳数">
    <input id="latency" value="0-999" title="延迟范围(优选)">
    <label><input id="download" type="checkbox"> 下载测速</label>
    <input id="url" placeholder="测速地址(auto)" style="flex:2">
  </div>
  <label>目标（每行一个: IP / 域名[:端口] / CIDR / 区间）</label>
  <textarea id="targets" placeholder="1.1.1.1&#10;example.com:443"></textarea>
  <div class="row">
    <button onclick="startJob()">开始任务</button>
    <button onclick="loadJobs()">刷新</button>
    <span id="status"></span>
  </div>
  <label>事件流（SSE 实时推送）</label>
  <div id="events"></div>
</div>
<div class="panel"><b>任务历史</b><div id="jobs"></div></div>
<div class="panel"><b>结果</b> <a id="export" href="#">导出 CSV</a>
  <div style="overflow:auto;max-height:360px"><table id="table"></table></div>
</div>
<script>
let current=null, es=null;
const $=id=>document.getElementById(id);
function status(t){$("status").textContent=t}
function log(t){const d=document.createElement("div");d.textContent=t;$("events").appendChild(d);$("events").scrollTop=1e9}
async function startJob(){
  const targets=$("targets").value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  if(!targets.length){status("请先输入目标");return}
  const mode=$("mode").value, payload={mode,targets};
  if(mode==="line"){payload.worker=+$("worker").value||15;payload.max_hops=+$("max_hops").value||12}
  else{
    const [lo,hi]=$("latency").value.split("-").map(Number);
    payload.latency_min=lo||0;payload.latency_max=hi||999;
    payload.download_speed=$("download").checked;
    payload.url=$("url").value.trim()||"auto";
  }
  const r=await fetch("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const data=await r.json();
  if(!r.ok){status(data.error);return}
  current=data.id;$("events").innerHTML="";openEvents(current);loadJobs();
}
function openEvents(id){
  if(es)es.close();
  es=new EventSource("/api/jobs/"+id+"/events");
  es.onmessage=m=>{
    const e=JSON.parse(m.data);
    if(e.type==="job_done"){es.close();status(e.error?"任务失败":"任务完成");loadDetail(id);loadJobs()}
    else log(e.type+" "+JSON.stringify(e).slice(0,300));
  };
}
async function loadJobs(){
  const r=await fetch("/api/jobs");const data=await r.json();
  $("jobs").innerHTML="";
  for(const j of data.jobs){
    const d=document.createElement("div");
    d.textContent=(j.mode==="line"?"线路":"优选")+" "+j.status+" "+j.result_count+"条";
    d.onclick=()=>loadDetail(j.id);
    $("jobs").appendChild(d);
  }
}
async function loadDetail(id){
  const r=await fetch("/api/jobs/"+id);if(!r.ok)return;const j=await r.json();
  const t=$("table");t.innerHTML="";
  const tr=document.createElement("tr");
  for(const h of j.headers){const th=document.createElement("th");th.textContent=h;tr.appendChild(th)}
  t.appendChild(tr);
  for(const row of j.rows){
    const tr2=document.createElement("tr");
    for(const c of row){const td=document.createElement("td");td.textContent=c;tr2.appendChild(td)}
    t.appendChild(tr2);
  }
  $("export").href="/api/jobs/"+id+"/export";
}
loadJobs();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("必须为正整数") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("必须为正整数")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trace",
        description="线路探测 / 在线优选",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog="示例:\n"
               "  trace.py -t line -i ip.txt -o result.csv\n"
               "  trace.py -m web --port 51917")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-m", "--mode", choices=("cli", "web"), default="cli",
                        help="前端模式: cli（终端）/ web（本地 Web 控制台）")
    parser.add_argument("-t", "--task", choices=("line", "optimize"), default="line",
                        help="任务类型: 线路探测 / 在线优选")
    parser.add_argument("-i", "--input", help="目标/IP 文件（每行一个）")
    parser.add_argument("-o", "--output", help="结果文件（默认 result.csv / result_optimize.csv）")
    parser.add_argument("-r", "--worker", type=_positive_int, help=f"线路探测并发（默认 {DEFAULT_WORKER}）")
    parser.add_argument("-mh", "--max-hops", type=_positive_int, help=f"最大跳数（默认 {DEFAULT_MAX_HOPS}）")
    parser.add_argument("-f", "--filter-workers", type=_positive_int, help="优选筛选并发")
    parser.add_argument("-d", "--download-workers", type=_positive_int, help="优选测速并发")
    parser.add_argument("-u", "--url", help="下载测速地址（配合 --download-speed）")
    parser.add_argument("--latency-min", type=int, default=0, help="优选延迟下限 (ms)")
    parser.add_argument("--latency-max", type=int, default=999, help="优选延迟上限 (ms)")
    parser.add_argument("--download-speed", action="store_true", help="启用下载测速")
    parser.add_argument("--port", type=int, default=51917, help="Web 监听端口")
    parser.add_argument("--no-browser", action="store_true", help="Web 模式不自动打开浏览器")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.mode == "web":
        web_main(args)
    else:
        cli_main(args)


if __name__ == "__main__":
    main()
