"""trace - 线路探测 / 在线优选前端示例（CLI + Web 双界面）.

基于 scripts/tracev2.py（CLI）与 scripts/trace_webv2.py（Web 控制台）

特点:

- 零第三方依赖，仅使用 Python 标准库；
- 通过 JSON Lines 事件流对接 Go 后端 main.exe（-nexttrace / -optimize-probe）；
- 同一套「目标解析 -> 后端任务 -> 事件流 -> 结果整理 -> 导出」核心，
  同时驱动终端 CLI 与本地 Web 控制台两种前端；
- 示例移除了商业许可门槛，代码完全开放，可直接学习、裁剪与二次分发。

架构::

    targets.txt -> trace.py -> main.exe -> JSON Lines 事件流 -> CLI / Web 渲染
                     (前端)       (Go 后端)       (SSE / 终端进度)

使用::

    py scripts/trace.py -t line -i ip.txt -o result.csv
    py scripts/trace.py -m web --port 51917
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _force_utf8():
    """让 Windows 控制台与标准流统一使用 UTF-8，避免中文乱码。"""
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_force_utf8()

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _is_frozen():
    return bool(getattr(sys, "frozen", False))


def _app_dir():
    if _is_frozen():
        return Path(sys.executable).resolve().parent
    return PROJECT_ROOT


APP_DIR = _app_dir()
DATA_DIR = APP_DIR / "data"


def _first_existing(*candidates):
    """按优先级返回第一个存在的文件，全部缺失时返回 None。"""
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file():
            return str(path)
    return None


MAIN_EXE = _first_existing(
    os.environ.get("TRACE_MAIN_EXE"),
    APP_DIR / "main.exe",
    PROJECT_ROOT / "main.exe",
    PROJECT_ROOT / "dist" / "main.exe",
    PROJECT_ROOT / "backend" / "main.exe",
) or str(APP_DIR / "main.exe")

HISTORY_FILE = DATA_DIR / "history.json"
HISTORY_LOCK = threading.Lock()
HISTORY_PER_TOOL = 50
EVENT_CAP_PER_JOB = 2000
RESULT_DISPLAY_COUNT = 10

TRACE_BATCH_SIZE = 100
IDLE_TIMEOUT = 120.0
PROCESS_TIMEOUT = 30 * 60.0
PROGRESS_LINE_WIDTH = 78

DEFAULT_WORKER = 15
DEFAULT_DOWNLOAD_WORKER = 5
DEFAULT_MAX_HOPS = 12
DEFAULT_FILTER_WORKERS = 200
DEFAULT_SLIM_WORKERS = 32
DEFAULT_URL = "auto"
MODE_TARGET_LIMITS = {"line": 100, "match": 100, "optimize": 100000}

TRACE_HEADERS = ["IP地址", "ASN", "所属线路", "主机名", "运营商", "状态"]
OPTIMIZE_HEADERS = [
    "IP地址", "端口号", "TLS", "HTTP", "丢包率", "网络延迟", "下载速度",
    "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市",
    "ASN号码", "ASN组织", "ProxyIP", "风险等级",
]

_TARGET_TOKEN_RE = re.compile(
    r"\[[0-9A-Fa-f:.]+\](?::\d+)?"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"
    r"|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])*)+(?::\d+)?")
_BARE_IPV6_RE = re.compile(r"[0-9A-Fa-f:]+")
_IP_PART = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9A-Fa-f:]+)"
_CIDR_RE = re.compile(_IP_PART + r"/\d{1,3}")
_RANGE_RE = re.compile(_IP_PART + r"-" + _IP_PART)
# ---------------------------------------------------------------------------
# 展示辅助
# ---------------------------------------------------------------------------


def format_display_ip(value):
    """IPv6 地址补上方括号以规范展示（如 [2606:4700::1]）。"""
    text = str(value or "").strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    return f"[{text}]" if addr.version == 6 else text


def _display_field(value):
    """线路探测单元格规范化：缺失值（None/空）统一显示为 'error'。"""
    text = str(value or "").strip()
    if not text or text.lower() == "none":
        return "error"
    return text


def _display_width(text):
    width = 0
    for ch in str(text):
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _print_progress(text, end=""):
    terminal_width = shutil.get_terminal_size((PROGRESS_LINE_WIDTH, 1)).columns
    line_width = max(1, terminal_width - 1)
    pad = " " * max(0, line_width - _display_width(text))
    print("\r" + str(text) + pad, end=end, flush=True)


def _print_table(headers, rows):
    def width_of(text):
        return _display_width(text)

    widths = []
    for index, header in enumerate(headers):
        width = width_of(header)
        for row in rows:
            width = max(width, width_of(row[index]) if index < len(row) else 0)
        widths.append(width)

    def pad(text, width):
        return str(text) + " " * max(0, width - width_of(text))

    print("  ".join(pad(header, widths[index]) for index, header in enumerate(headers)))
    print("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in rows:
        cells = [pad(cell, widths[index]) for index, cell in enumerate(row[:len(headers)])]
        print("  ".join(cells))


def trace_row(event):
    """把后端 result 事件整理为定长表格行。"""
    asn = _display_field(event.get("matched_asn"))
    line = _display_field(event.get("line_type"))
    host = _display_field(event.get("hostname"))
    isp = _display_field(event.get("isp"))
    status = ("失败" if (event.get("error") or any(
        field in ("error", "—") for field in (asn, line, host, isp))) else "成功")
    return [format_display_ip(event.get("target", "")), asn, line, host, isp, status]


def _opt_column_off(idx, payload):
    """在线优选列是否因对应参数选项关闭而应显示为 '—'。"""
    payload = payload or {}
    if idx == 6:
        return not bool(payload.get("download_speed"))
    if idx == 15:
        return not bool(payload.get("proxyip_check"))
    if idx == 16:
        return not bool(payload.get("risk_check"))
    return False


def _normalize_opt_cell(value, idx, payload):
    """在线优选单元格规范化：选项关闭列缺失 -> '—'；其余缺失 -> 'error'。"""
    if isinstance(value, str):
        text = value.strip()
        if not text or text.lower() == "none":
            return "—" if _opt_column_off(idx, payload) else "error"
    return value


def _normalize_opt_row(row, payload):
    """把后端 opt_record 行规范化为定长表格行，容忍短行/非列表输入。"""
    values = row if isinstance(row, list) else []
    normalized = [_normalize_opt_cell(value, i, payload) for i, value in enumerate(values)]
    if len(normalized) < len(OPTIMIZE_HEADERS):
        normalized += [""] * (len(OPTIMIZE_HEADERS) - len(normalized))
    return normalized


def _cell_number(value):
    match = re.search(r"^-?\d+(?:\.\d+)?", str(value or "").strip())
    return float(match.group(0)) if match else None


def _sort_optimize_rows(rows, passes, download_speed):
    if download_speed:
        def speed_key(row):
            speed = _cell_number(row[6]) if len(row) > 6 else None
            return (1, 0.0) if speed is None else (0, -speed)
        key = speed_key
    else:
        def loss_latency_key(row):
            loss = _cell_number(row[4]) if len(row) > 4 else None
            latency = _cell_number(row[5]) if len(row) > 5 else None
            return (0 if loss is not None else 1, loss if loss is not None else 0,
                    0 if latency is not None else 1, latency if latency is not None else 0)
        key = loss_latency_key
    ordered = sorted(zip(rows, passes), key=lambda item: key(item[0]))
    return [item[0] for item in ordered], [item[1] for item in ordered]
# ---------------------------------------------------------------------------
# 目标解析（CLI 严格模式；Web 模式由后端 main.exe 解析）
# ---------------------------------------------------------------------------


def _validate_target_token(token, line_number):
    """校验显式端口与字面 IP，防止垃圾输入绕过正则。"""
    host = token
    port = None
    if token.startswith("["):
        end = token.find("]")
        host = token[1:end]
        rest = token[end + 1:]
        if rest:
            port = rest[1:]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(f"第 {line_number} 行不是有效的方括号 IPv6: '{token}'")
        if address.version != 6:
            raise ValueError(f"第 {line_number} 行方括号语法仅支持 IPv6: '{token}'")
    elif token.count(":") == 1:
        host, port = token.rsplit(":", 1)
    if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise ValueError(f"第 {line_number} 行端口必须为 1-65535: '{token}'")
    if "." in host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
                raise ValueError(f"第 {line_number} 行不是有效 IPv4: '{token}'")
    return token


def _extract_target_token(line, line_number):
    """清洗一行输入并提取唯一目标 token（支持 IPv4/IPv6/域名[:端口]）。"""
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    tokens = _TARGET_TOKEN_RE.findall(content)
    if len(tokens) == 1 and tokens[0] == content:
        return _validate_target_token(tokens[0], line_number)
    if content.count(":") >= 2 and "[" not in content and _BARE_IPV6_RE.fullmatch(content):
        candidate, _, port_text = content.rpartition(":")
        if port_text.isdigit() and len(port_text) <= 5:
            try:
                ipaddress.ip_address(candidate)
                return _validate_target_token(candidate, line_number)
            except ValueError:
                pass
        try:
            ipaddress.ip_address(content)
            return _validate_target_token(content, line_number)
        except ValueError:
            pass
    hint = "（支持裸 IPv6 或方括号写法，如 2606:4700:: / [2606:4700::]）" \
        if "[" not in content and content.count(":") > 1 else ""
    raise ValueError(f"第 {line_number} 行不是有效的单个目标/IP: '{line.strip()}'{hint}")


def _extract_optimize_token(line, line_number):
    """提取在线优选目标：IP[:端口]、CIDR、IP 区间（展开由后端完成）。"""
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    if _CIDR_RE.fullmatch(content):
        return content
    if _RANGE_RE.fullmatch(content):
        return content
    return _extract_target_token(content, line_number)


def estimate_expand_count(tokens, limit):
    """快速估算展开后的地址总数（重叠网段先合并，与后端语义一致）。"""
    spans_v4, spans_v6 = [], []
    total = 0

    def merge_spans(spans):
        if not spans:
            return 0
        count = 0
        spans.sort()
        cur_start, cur_end = spans[0]
        for start, end in spans[1:]:
            if start <= cur_end + 1:
                if end > cur_end:
                    cur_end = end
                continue
            count += cur_end - cur_start + 1
            cur_start, cur_end = start, end
        return count + (cur_end - cur_start + 1)

    for token in tokens:
        if _CIDR_RE.fullmatch(token):
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise ValueError(f"无效 CIDR: {token}")
            span = (int(network.network_address), int(network.broadcast_address))
            (spans_v4 if network.version == 4 else spans_v6).append(span)
        elif _RANGE_RE.fullmatch(token):
            start_text, end_text = token.split("-", 1)
            try:
                start = ipaddress.ip_address(start_text.strip())
            except ValueError:
                raise ValueError(f"无效 IP 区间: {token}")
            try:
                end = ipaddress.ip_address(end_text.strip())
            except ValueError:
                raise ValueError(f"无效 IP 区间: {token}")
            if start.version != end.version or int(start) > int(end):
                raise ValueError(f"无效 IP 区间: {token}")
            count = int(end) - int(start) + 1
            if count > limit:
                raise ValueError(f"IP 区间最多展开 {limit} 个地址: {token}")
            span = (int(start), int(end))
            (spans_v4 if start.version == 4 else spans_v6).append(span)
        else:
            total += 1
    total += merge_spans(spans_v4) + merge_spans(spans_v6)
    if total > limit:
        raise ValueError(f"目标展开后最多 {limit} 个地址")
    return total


def read_lines(file_path):
    try:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise RuntimeError(f"无法读取文件 '{file_path}': {exc}") from exc


def read_targets(file_path):
    """读取线路探测目标：支持 CSV（表头 标签/目标）或一行一个目标。"""
    lines = read_lines(file_path)
    try:
        csv_rows = list(csv.DictReader(lines))
        has_header = bool(csv_rows and csv_rows[0])
    except csv.Error:
        has_header = False
        csv_rows = []
    fieldnames = {}
    if has_header:
        fieldnames = {str(name).strip(): name for name in csv_rows[0].keys() if name}
    label_key = fieldnames.get("标签")
    target_key = next((fieldnames.get(name) for name in ("目标", "IP地址", "域名")
                       if fieldnames.get(name)), None)
    entries = []
    if label_key and target_key:
        for line_number, row in enumerate(csv_rows, 2):
            label = str(row.get(label_key) or "").strip()
            target_text = str(row.get(target_key) or "").strip()
            if not label and not target_text:
                continue
            if not label or not target_text:
                raise RuntimeError(f"CSV 第 {line_number} 行的标签和目标不能为空")
            token = _extract_target_token(target_text, line_number)
            if token:
                entries.append({"label": label, "host": token})
    else:
        for line_number, line in enumerate(lines, 1):
            token = _extract_target_token(line, line_number)
            if token:
                entries.append({"label": "", "host": token})
    if len(entries) > MODE_TARGET_LIMITS["line"]:
        raise RuntimeError(f"线路探测目标最多 {MODE_TARGET_LIMITS['line']} 个地址，当前 {len(entries)} 个")
    return _dedup_entries(entries)


def read_optimize_targets(file_path):
    """读取在线优选目标：一行一个 IP[:端口] / CIDR / IP 区间。"""
    lines = read_lines(file_path)
    tokens = []
    for line_number, line in enumerate(lines, 1):
        token = _extract_optimize_token(line, line_number)
        if token:
            tokens.append(token)
    if not tokens:
        return []
    try:
        estimate_expand_count(tokens, MODE_TARGET_LIMITS["optimize"])
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    return _dedup_entries([{"label": "", "host": token, "raw": token} for token in tokens])


def _dedup_entries(entries):
    seen = set()
    result = []
    for entry in entries:
        key = (entry["host"], entry.get("port") or "")
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result
# ---------------------------------------------------------------------------
# 后端交互：main.exe 事件流
# ---------------------------------------------------------------------------


def verify_backend():
    if not os.path.isfile(MAIN_EXE):
        print("[-] 错误: 未找到 main.exe。请运行 build.bat 构建选项 1，"
              "或在 backend 目录执行 go build -o ..\\dist\\main.exe .",
              file=sys.stderr)
        sys.exit(1)


def _decode_line(raw):
    """解码后端输出：优先 UTF-8，兜底 gb18030（兼容旧版 Windows 控制台）。"""
    if isinstance(raw, str):
        return raw
    data = bytes(raw or b"")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("gb18030", errors="replace")


def _kill_process_tree(proc):
    if proc is None or proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


def build_match_cmd(input_file, worker, max_hops):
    """线路探测命令：main.exe -nexttrace（nexttrace-core 式探测）。"""
    return [MAIN_EXE, "-nexttrace", "-i", input_file, "-input-json=true",
            "-r", str(worker), "-max-hops", str(max_hops)]


def build_optimize_cmd(input_file, payload):
    """在线优选命令：main.exe -optimize-probe（筛选->测速->检测->整理）。"""
    cmd = [MAIN_EXE, "-optimize-probe", "-i", input_file, "-input-json=true",
           "-f", str(payload.get("filter_workers", DEFAULT_FILTER_WORKERS)),
           "-download-workers", str(payload.get("download_workers", DEFAULT_DOWNLOAD_WORKER)),
           "-latency-min", str(payload.get("latency_min", 0)),
           "-latency-max", str(payload.get("latency_max", 999))]
    if payload.get("subnet_sample"):
        cmd += ["-s", str(payload.get("slim_workers") or DEFAULT_SLIM_WORKERS)]
    if payload.get("proxyip_check"):
        cmd += ["-proxyip-check=true"]
    if payload.get("risk_check"):
        cmd += ["-risk-check=true"]
    if payload.get("download_speed"):
        cmd += ["-url", str(payload.get("url") or DEFAULT_URL)]
    return cmd


def _backend_env():
    env = os.environ.copy()
    env["TRACE_DATA_DIR"] = str(DATA_DIR)
    return env


def stream_backend(cmd, error_label="main 异常退出"):
    """启动 main.exe 并逐行产出 JSON 事件；空闲时产出 stream_heartbeat。"""
    env = _backend_env()
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=False, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        raise RuntimeError(f"无法启动 main.exe: {exc}") from exc

    stderr_lines = []
    stdout_queue = queue.Queue()

    def read_stdout():
        try:
            for raw in proc.stdout:
                stdout_queue.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            stdout_queue.put(None)

    def drain_stderr():
        try:
            for raw in proc.stderr:
                stderr_lines.append(_decode_line(raw))
        except (OSError, ValueError):
            pass

    threading.Thread(target=read_stdout, name="main-stdout", daemon=True).start()
    threading.Thread(target=drain_stderr, name="main-stderr", daemon=True).start()

    stream_complete = False
    process_started = time.monotonic()
    last_output = time.monotonic()
    try:
        while True:
            try:
                line = stdout_queue.get(timeout=0.5)
            except queue.Empty:
                if time.monotonic() - process_started >= PROCESS_TIMEOUT:
                    raise RuntimeError(f"main.exe 运行超过 {PROCESS_TIMEOUT:.0f} 秒，已终止")
                if time.monotonic() - last_output >= IDLE_TIMEOUT:
                    raise RuntimeError(f"main.exe 超过 {IDLE_TIMEOUT:.0f} 秒没有输出，已终止")
                yield {"type": "stream_heartbeat"}
                continue
            if line is None:
                break
            last_output = time.monotonic()
            text = _decode_line(line).strip()
            if not text:
                continue
            try:
                yield json.loads(text)
            except json.JSONDecodeError:
                yield {"type": "log", "message": text}
        stream_complete = True
    finally:
        aborted = not stream_complete
        if aborted:
            _kill_process_tree(proc)
        try:
            ret = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc)
            ret = proc.wait()
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        stderr = "".join(stderr_lines).strip()
        if ret != 0 and not aborted:
            raise RuntimeError(f"{error_label} (code={ret}): {stderr}")
# ---------------------------------------------------------------------------
# CSV 导出
# ---------------------------------------------------------------------------


class AtomicCsvWriter:
    """先写临时文件再原子替换，避免导出中断留下半个文件。"""

    def __init__(self, output_path, headers, delimiter=","):
        if not isinstance(output_path, str) or not output_path.strip():
            raise OSError(f"无效的导出路径: {output_path!r}")
        self._output_path = os.path.abspath(output_path)
        output_dir = os.path.dirname(self._output_path) or os.curdir
        fd, self._tmp_path = tempfile.mkstemp(
            prefix=".trace_csv_", suffix=".tmp", dir=output_dir)
        self._fh = os.fdopen(fd, "w", newline="", encoding="utf-8-sig")
        self._csv = csv.writer(self._fh, delimiter=delimiter)
        self._csv.writerow(headers)

    def write_row(self, row):
        self._csv.writerow(row)

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
            if exc_type is None:
                os.replace(self._tmp_path, self._output_path)
            else:
                os.remove(self._tmp_path)
        except OSError:
            try:
                os.remove(self._tmp_path)
            except OSError:
                pass
            raise
        return False


def export_delimiter(output_path):
    """按导出文件后缀选择分隔符：txt 用制表符（TSV），其余用逗号。"""
    if isinstance(output_path, str) and os.path.splitext(output_path)[1].lower() == ".txt":
        return "\t"
    return ","


def export_csv_text(headers, rows, delimiter=","):
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def write_csv(rows, headers, output_path):
    try:
        with AtomicCsvWriter(output_path, headers, export_delimiter(output_path)) as writer:
            for row in rows:
                writer.write_row(row)
    except OSError as exc:
        print(f"[-] 错误: 无法写入文件 '{output_path}'（{exc}），请检查文件是否被打开或占用")
        raise
    print("-" * 60)
    print(f"[+] 结果已生成: {output_path}（共 {len(rows)} 行）")
# ---------------------------------------------------------------------------
# CLI 前端
# ---------------------------------------------------------------------------


def prompt_task():
    print("[+] 请选择任务类型")
    print("    1. 线路探测")
    print("    2. 在线优选")
    while True:
        try:
            choice = input("请选择 (1/2): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "line"
        if choice == "1":
            return "line"
        if choice == "2":
            return "optimize"
        print("[-] 无效输入，请输入 1 或 2")


def run_trace_cli(entries, worker, max_hops):
    """线路探测：分批调用后端，渲染进度，返回去重后的结果行。"""
    rows = []
    seen = set()
    done = 0
    total = len(entries)
    succeeded = 0
    failed = 0
    trace_started = None
    progress_shown = False

    def render(label):
        elapsed = time.monotonic() - trace_started if trace_started else 0.0
        threads = min(worker, max(total, 1))
        _print_progress(
            f"[+] 线路探测 {done}/{total} 用时: {elapsed:.1f}s "
            f"{label}: {succeeded}  失败: {failed}  并发: {threads}")

    for batch_start in range(0, len(entries), TRACE_BATCH_SIZE):
        batch = entries[batch_start:batch_start + TRACE_BATCH_SIZE]
        fd, tmp_path = tempfile.mkstemp(prefix="trace_hosts_", suffix=".txt", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tf:
                for entry in batch:
                    tf.write(json.dumps(
                        {"host": entry["host"], "label": entry.get("label", "")},
                        ensure_ascii=False, separators=(",", ":")) + "\n")
            for ev in stream_backend(build_match_cmd(tmp_path, worker, max_hops)):
                ev_type = ev.get("type")
                if ev_type == "trace_summary":
                    trace_started = time.monotonic()
                    if ev.get("count"):
                        total = ev["count"]
                    continue
                if ev_type in ("stream_heartbeat", "progress_heartbeat"):
                    if trace_started is not None:
                        render("成功")
                        progress_shown = True
                    continue
                if ev_type != "result":
                    continue
                row = trace_row(ev)
                ip = ev.get("target", "")
                if ip and ip not in seen:
                    seen.add(ip)
                    rows.append(row)
                done += 1
                if row[-1] == "失败":
                    failed += 1
                else:
                    succeeded += 1
                if trace_started is not None:
                    render("成功")
                    progress_shown = True
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    if progress_shown:
        print()
    return rows


def run_optimize_cli(entries, output_path, payload):
    """在线优选：调用后端全流程，渲染各阶段进度，整理结果并导出。"""
    total = len(entries)
    if payload.get("download_speed") and str(payload.get("url") or "").strip().lower() != "auto":
        parsed = urlparse(payload.get("url"))
        if parsed.scheme != "https" or not parsed.hostname:
            raise RuntimeError("无效的下载测速地址（例如: https://example.com/ 或 完整地址）")
    stage_names = {"subnet": "子网精简", "filter": "数据筛选", "proxyip": "ProxyIP 检测",
                   "risk": "风险检测", "download": "下载测速", "organize": "数据整理"}
    results = []
    started = time.monotonic()
    last_line = ""

    def render(text):
        nonlocal last_line
        last_line = text
        _print_progress(text)

    fd, tmp_path = tempfile.mkstemp(prefix="trace_optimize_", suffix=".txt", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            for entry in entries:
                item = {"host": entry["host"], "raw": entry.get("raw") or entry["host"]}
                if entry.get("port"):
                    item["port"] = entry["port"]
                tf.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
        for ev in stream_backend(build_optimize_cmd(tmp_path, payload)):
            ev_type = ev.get("type")
            if ev_type == "opt_stage":
                phase = ev.get("phase")
                if ev.get("status") == "skipped":
                    render(f"[+] {stage_names.get(phase, phase)}: 已跳过")
            elif ev_type == "opt_filter_progress":
                done = ev.get("done", 0)
                available = ev.get("available", 0)
                phase = ev.get("phase") or "filter"
                name = stage_names.get(phase, phase)
                render(f"[+] {name} {done}/{ev.get('total', total)} "
                       f"用时: {time.monotonic() - started:.1f}s 通过: {available}  "
                       f"未通过: {done - available}  并发: {ev.get('workers', '?')}")
            elif ev_type == "opt_download_progress":
                render(f"[+] 下载测速 {ev.get('done', 0)}/{ev.get('total', 0)} "
                       f"用时: {time.monotonic() - started:.1f}s "
                       f"合格: {ev.get('qualified', 0)}  不合格: {ev.get('unqualified', 0)}")
            elif ev_type == "opt_service_progress":
                name = stage_names.get(ev.get("phase"), "服务检测")
                aborted = "  已中止(接口不可用)" if ev.get("aborted") else ""
                render(f"[+] {name} {ev.get('done', 0)}/{ev.get('total', 0)} "
                       f"用时: {time.monotonic() - started:.1f}s 成功: {ev.get('ok', 0)}  "
                       f"失败: {ev.get('fail', 0)}  频控: {ev.get('limited', 0)}{aborted}")
            elif ev_type == "opt_record":
                if ev.get("record") and ev.get("row"):
                    results.append({"record": ev["record"],
                                    "row": _normalize_opt_row(ev["row"], payload),
                                    "display": ev.get("display", True)})
    finally:
        if last_line:
            print()
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    if not results:
        print("[-] 提示: 无目标/IP 通过筛选，无结果可输出")
        return
    summarize_optimize(results, output_path)


def summarize_optimize(results, output_path):
    """在线优选结果整理：按丢包/延迟或下载速度排序，展示 TOP10 并导出。"""
    rows = [item["row"] for item in results]
    passes = [bool(item["record"].get("qualified")) for item in results]
    download_speed = bool((results[0]["record"] or {}).get("download_speed"))
    if not download_speed:
        download_speed = any(_cell_number(row[6]) is not None for row in rows)
    if download_speed:
        kept = [(row, passed) for row, passed in zip(rows, passes)
                if _cell_number(row[6]) is not None and _cell_number(row[6]) > 0]
        rows = [row for row, _ in kept]
        passes = [passed for _, passed in kept]
    rows, passes = _sort_optimize_rows(rows, passes, download_speed)
    print("-" * 60)
    print(f"[+] 在线优选结果 TOP{min(RESULT_DISPLAY_COUNT, len(rows))}:")
    _print_table(OPTIMIZE_HEADERS, rows[:RESULT_DISPLAY_COUNT])
    write_csv(rows, OPTIMIZE_HEADERS, output_path)


def show_line_results(rows, output_path):
    pairs = [row for row in rows if row[-1] == "成功"]
    print("-" * 60)
    print(f"[+] 线路探测结果 TOP{min(RESULT_DISPLAY_COUNT, len(pairs))}:")
    _print_table(TRACE_HEADERS, pairs[:RESULT_DISPLAY_COUNT])
    write_csv(rows, TRACE_HEADERS, output_path)


def cli_main(args):
    verify_backend()
    task = args.task
    if task is None:
        if sys.stdin.isatty():
            task = prompt_task()
        else:
            task = "line"
    try:
        entries = (read_targets(args.input) if task == "line"
                   else read_optimize_targets(args.input))
    except (RuntimeError, ValueError) as exc:
        print(f"[-] 错误: {exc}")
        sys.exit(1)
    if not entries:
        print("[-] 提示: 输入文件中未读取到有效目标/IP")
        sys.exit(1)
    print(f"[+] 已读取目标/IP: {len(entries)} 条（去重后）")
    output = args.output or ("result.csv" if task == "line" else "result_optimize.csv")
    ext = os.path.splitext(output)[1].lower()
    if ext not in (".csv", ".txt"):
        print(f"[-] 错误: 输出文件后缀格式错误（需为 .csv 或 .txt）: '{output}'")
        sys.exit(1)
    try:
        if task == "line":
            rows = run_trace_cli(entries, args.worker or DEFAULT_WORKER,
                                 args.max_hops or DEFAULT_MAX_HOPS)
            show_line_results(rows, output)
        else:
            payload = {
                "filter_workers": args.filter_workers or DEFAULT_FILTER_WORKERS,
                "download_workers": args.download_workers or DEFAULT_DOWNLOAD_WORKER,
                "slim_workers": args.slim_workers or DEFAULT_SLIM_WORKERS,
                "latency_min": args.latency_min,
                "latency_max": args.latency_max,
                "proxyip_check": args.proxyip_check,
                "risk_check": args.risk_check,
                "download_speed": args.download_speed,
                "subnet_sample": args.subnet_sample,
                "url": args.url or DEFAULT_URL,
            }
            run_optimize_cli(entries, output, payload)
    except RuntimeError as exc:
        print(f"[-] 错误: {exc}")
        sys.exit(1)
# ---------------------------------------------------------------------------
# Web 前端：任务管理 + SSE
# ---------------------------------------------------------------------------

JOBS = {}


def load_json_file(path, default=None):
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError, TypeError):
        return default


def _atomic_write_text(path, text):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def save_json_file(path, payload):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=1))
    except OSError:
        pass


def save_history():
    with HISTORY_LOCK:
        snapshot = {
            job_id: {"meta": job["meta"], "events": job["events"][-EVENT_CAP_PER_JOB:],
                     "result_rows": job.get("result_rows", [])}
            for job_id, job in JOBS.items()
            if job["meta"].get("status") != "running"
        }
    save_json_file(HISTORY_FILE, snapshot)


def load_history():
    payload = load_json_file(HISTORY_FILE, {})
    if not isinstance(payload, dict):
        return
    restored = {}
    with HISTORY_LOCK:
        for job_id, entry in payload.items():
            if not isinstance(entry, dict):
                continue
            meta, events = entry.get("meta"), entry.get("events")
            if not isinstance(meta, dict) or not isinstance(events, list):
                continue
            result_rows = entry.get("result_rows", [])
            restored[job_id] = {
                "events": [event for event in events if isinstance(event, dict)],
                "event_offset": 0,
                "process": None,
                "result_rows": result_rows if isinstance(result_rows, list) else [],
                "meta": meta,
            }
        JOBS.update(restored)


def prune_history():
    """每个任务类型各保留最近 HISTORY_PER_TOOL 条历史。"""
    with HISTORY_LOCK:
        by_mode = {}
        for job_id in list(JOBS):
            mode = JOBS[job_id]["meta"].get("mode", "match")
            by_mode.setdefault(mode, []).append(job_id)
        for mode_jobs in by_mode.values():
            mode_jobs.sort(key=lambda job_id: JOBS[job_id]["meta"].get("created", 0))
            for job_id in mode_jobs[:-HISTORY_PER_TOOL]:
                JOBS.pop(job_id, None)


def append_event(job_id, event):
    with HISTORY_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        event_type = event.get("type")
        mode = job["meta"]["mode"]
        store = job.setdefault("result_rows", [])
        if mode == "match" and event_type == "result":
            row = trace_row(event)
            store.append({"row": row, "pass": row[-1] == "成功"})
        elif mode == "optimize" and event_type == "opt_record":
            store.append({"row": _normalize_opt_row(event.get("row"), job["meta"].get("payload")),
                          "pass": bool((event.get("record") or {}).get("qualified"))})
        events = job["events"]
        events.append(event)
        overflow = len(events) - EVENT_CAP_PER_JOB
        if overflow > 0:
            del events[:overflow]
            job["event_offset"] = job.get("event_offset", 0) + overflow


def run_job(job_id, payload):
    """后台线程：启动后端进程，把 JSON Lines 事件写入任务队列。"""
    job_entry = JOBS.get(job_id)
    if job_entry is None:
        return
    fd, path = tempfile.mkstemp(prefix="trace-web-", suffix=".txt")
    os.close(fd)
    try:
        try:
            mode = payload.get("mode", "match")
            with open(path, "w", encoding="utf-8") as f:
                for target in payload.get("targets", []):
                    f.write(json.dumps({"token": target}, ensure_ascii=False) + "\n")
            cmd = (build_match_cmd(path, payload.get("worker", DEFAULT_WORKER),
                                   payload.get("max_hops", DEFAULT_MAX_HOPS))
                   if mode == "match" else build_optimize_cmd(path, payload))
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=False, env=_backend_env(),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            job_entry["process"] = process
            last_message = ""
            for raw_line in process.stdout:
                line = _decode_line(raw_line)
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {"type": "log", "message": line.rstrip()}
                if not isinstance(event, dict):
                    event = {"type": "log", "message": str(event)}
                if event.get("type") == "log" and event.get("message"):
                    last_message = event["message"]
                if event.get("type") == "opt_record" and mode == "optimize":
                    opt_row = event.get("row")
                    if isinstance(opt_row, list):
                        event["row"] = [_normalize_opt_cell(value, i, payload)
                                        for i, value in enumerate(opt_row)]
                append_event(job_id, event)
                event_type = event.get("type")
                if event_type == "result" and mode == "match":
                    if trace_row(event)[-1] == "成功":
                        job_entry["meta"]["result_count"] += 1
                elif event_type == "opt_record" and mode == "optimize":
                    if (event.get("record") or {}).get("qualified"):
                        job_entry["meta"]["result_count"] += 1
            error = process.wait() != 0
            canceled = job_entry["meta"]["status"] == "canceled"
            append_event(job_id, {"type": "job_done", "error": error,
                                  "canceled": canceled,
                                  "message": None if canceled else (last_message or None)})
            if canceled:
                job_entry["meta"]["status"] = "canceled"
            elif job_entry["meta"]["status"] == "running":
                job_entry["meta"]["status"] = "failed" if error else "done"
            if error and not canceled:
                job_entry["meta"]["error"] = last_message or "任务执行失败"
        except Exception as exc:
            canceled = job_entry["meta"]["status"] == "canceled"
            message = str(exc) or exc.__class__.__name__
            job_entry["meta"]["error"] = message
            append_event(job_id, {"type": "job_done", "error": True,
                                  "canceled": canceled, "message": message})
            job_entry["meta"]["status"] = "canceled" if canceled else "failed"
        save_history()
        prune_history()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def launch_job(payload):
    job_id = os.urandom(8).hex()
    with HISTORY_LOCK:
        JOBS[job_id] = {
            "events": [], "event_offset": 0, "process": None,
            "meta": {"created": time.time(),
                     "mode": payload.get("mode", "match"),
                     "status": "running", "result_count": 0,
                     "target_count": len(payload.get("targets", [])),
                     "payload": payload},
        }
    threading.Thread(target=run_job, args=(job_id, payload), daemon=True).start()
    prune_history()
    return job_id


def job_summary(job_id, job):
    meta = job["meta"]
    return {"id": job_id,
            "mode": meta.get("mode", "match"),
            "created_text": time.strftime("%m-%d %H:%M:%S",
                                          time.localtime(meta.get("created", 0))),
            "target_count": meta.get("target_count", 0),
            "result_count": meta.get("result_count", 0),
            "status": meta.get("status", "done"),
            "error": meta.get("error")}


def job_detail(job_id, job):
    meta = job["meta"]
    payload = meta.get("payload") or {}
    mode = meta.get("mode", "match")
    headers = TRACE_HEADERS if mode == "match" else OPTIMIZE_HEADERS
    rows, passes = [], []
    for item in job.get("result_rows", []):
        row = item.get("row")
        if isinstance(row, list) and len(row) >= len(headers):
            rows.append(row)
            passes.append(bool(item.get("pass")))
    if mode == "optimize":
        download_speed = bool(payload.get("download_speed"))
        if not download_speed:
            download_speed = any(_cell_number(row[6]) is not None for row in rows)
        if download_speed:
            kept = [(row, passed) for row, passed in zip(rows, passes)
                    if _cell_number(row[6]) is not None and _cell_number(row[6]) > 0]
            rows = [row for row, _ in kept]
            passes = [passed for _, passed in kept]
        rows, passes = _sort_optimize_rows(rows, passes, download_speed)
    detail = job_summary(job_id, job)
    detail["headers"] = headers
    detail["all_results"] = rows
    detail["all_pass"] = passes
    detail["results"] = rows[:RESULT_DISPLAY_COUNT]
    detail["pass"] = passes[:RESULT_DISPLAY_COUNT]
    detail["targets"] = payload.get("targets", [])[:200]
    detail["parameters"] = {key: value for key, value in payload.items()
                            if key != "targets"}
    return detail


def cancel_job(job_id):
    with HISTORY_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return False
        if job["meta"]["status"] == "running":
            job["meta"]["status"] = "canceled"
            _kill_process_tree(job["process"])
    return True
# ---------------------------------------------------------------------------
# Web 前端：HTTP 服务
# ---------------------------------------------------------------------------

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trace Web (MIT 示例)</title>
<style>
:root{--bg:#0b0c10;--panel:#15171d;--line:#2a2d36;--fg:#e6e8ee;--dim:#8b90a0;--accent:#2997ff;--ok:#30d158;--bad:#ff453a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--dim);margin:0 0 18px;font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.panel h2{font-size:14px;margin:0 0 10px}
label{display:block;font-size:12px;color:var(--dim);margin:8px 0 4px}
input,select,textarea{width:100%;background:#0d0e13;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:inherit}
textarea{min-height:120px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>*{flex:1;min-width:120px}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font-weight:600}
button.ghost{background:#262a33;color:var(--fg)}
button:disabled{opacity:.5;cursor:not-allowed}
#events{height:200px;overflow:auto;background:#0d0e13;border:1px solid var(--line);border-radius:6px;padding:8px;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;white-space:nowrap}
th{color:var(--dim);position:sticky;top:0;background:var(--panel)}
a{color:var(--accent)}
.hidden{display:none}
#jobs div:hover{background:#1b1e27}
</style>
</head>
<body>
<div class="wrap">
<h1>Trace Web 示例</h1>
<p class="sub">线路探测 / 在线优选</p>
<div class="grid">
  <div class="panel">
    <h2>新建任务</h2>
    <label>任务类型</label>
    <select id="mode"><option value="match">线路探测</option><option value="optimize">在线优选</option></select>
    <label>目标/IP（每行一个，支持 IPv4/IPv6/域名[:端口]、CIDR、区间）</label>
    <textarea id="targets" placeholder="1.1.1.1&#10;2606:4700::1&#10;example.com:443"></textarea>
    <div class="row">
      <div><label>并发 workers</label><input id="worker" type="number" value="15" min="1"></div>
      <div><label>最大跳数（线路探测）</label><input id="max_hops" type="number" value="12" min="1"></div>
    </div>
    <div class="row hidden" id="opt_opts">
      <div><label>延迟范围 (ms)</label><input id="latency" value="0-999"></div>
      <div><label>下载测速 URL</label><input id="url" placeholder="auto / https://..."></div>
    </div>
    <div class="row">
      <label style="display:flex;align-items:center;gap:6px"><input id="proxyip" type="checkbox"> ProxyIP 检测</label>
      <label style="display:flex;align-items:center;gap:6px"><input id="risk" type="checkbox"> 风险检测</label>
      <label style="display:flex;align-items:center;gap:6px"><input id="download" type="checkbox"> 下载测速</label>
      <label style="display:flex;align-items:center;gap:6px"><input id="subnet" type="checkbox"> 子网精简</label>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px">
      <button id="start" onclick="startJob()">开始任务</button>
      <button class="ghost" id="stop" onclick="stopJob()" disabled>停止</button>
      <button class="ghost" onclick="loadJobs()">刷新历史</button>
    </div>
    <div id="status" style="margin-top:8px;font-size:12px;color:var(--dim)"></div>
    <label>事件流（SSE）</label>
    <div id="events"></div>
  </div>
  <div class="panel">
    <h2>任务历史 <span id="job_count" style="color:var(--dim);font-weight:normal"></span></h2>
    <div id="jobs"></div>
  </div>
</div>
<div class="panel" style="margin-top:16px">
  <h2>结果 <span id="export_link" style="font-weight:normal;font-size:12px"></span></h2>
  <div style="overflow:auto;max-height:420px">
    <table id="result_table"></table>
  </div>
</div>
</div>
<script>let current=null, es=null;
function $(id){return document.getElementById(id)}
function ev(t){const el=$("events");const d=document.createElement("div");d.textContent=t;el.appendChild(d);el.scrollTop=el.scrollHeight}
function setStatus(t){$("status").textContent=t}
$("mode").addEventListener("change",e=>{$("opt_opts").classList.toggle("hidden",e.target.value!=="optimize")});
async function postJSON(url,body){
  const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const data=await r.json();
  if(!r.ok)throw new Error(data.error||r.status);
  return data;
}
async function startJob(){
  const targets=$("targets").value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  if(!targets.length){setStatus("请先输入目标/IP");return}
  const mode=$("mode").value, payload={mode,targets};
  if(mode==="match"){
    payload.worker=parseInt($("worker").value)||15;
    payload.max_hops=parseInt($("max_hops").value)||12;
  }else{
    const parts=$("latency").value.split("-");
    payload.latency_min=parseInt(parts[0])||0;
    payload.latency_max=parseInt(parts[1])||999;
    payload.filter_workers=200; payload.download_workers=5;
    payload.proxyip_check=$("proxyip").checked;
    payload.risk_check=$("risk").checked;
    payload.download_speed=$("download").checked;
    payload.subnet_sample=$("subnet").checked;
    payload.url=$("url").value.trim()||"auto";
  }
  try{
    const res=await postJSON("/api/jobs",payload);
    current=res.id; $("start").disabled=true; $("stop").disabled=false;
    $("events").innerHTML=""; setStatus("任务已提交，等待事件流...");
    openEvents(current);
  }catch(err){setStatus(String(err))}
}
function openEvents(id){
  if(es)es.close();
  es=new EventSource("/api/jobs/"+id+"/events");
  es.onmessage=m=>{
    const e=JSON.parse(m.data);
    ev(e.type==="job_done"?JSON.stringify(e):e.type+" "+JSON.stringify(e).slice(0,400));
    if(e.type==="job_done"){
      es.close(); $("start").disabled=false; $("stop").disabled=true;
      setStatus(e.error?"任务失败："+(e.message||""):"任务完成");
      loadDetail(id); loadJobs();
    }
  };
}
async function stopJob(){
  if(!current)return;
  try{await fetch("/api/jobs/"+current,{method:"DELETE"});ev("[stop] 已请求停止")}
  catch(err){setStatus(String(err))}
}
async function loadJobs(){
  try{
    const r=await fetch("/api/jobs"); const data=await r.json();
    const box=$("jobs"); box.innerHTML="";
    $("job_count").textContent="("+data.jobs.length+")";
    for(const j of data.jobs){
      const d=document.createElement("div");
      d.style.cssText="display:flex;justify-content:space-between;gap:8px;padding:7px 0;border-bottom:1px solid var(--line);cursor:pointer";
      d.innerHTML="<span>"+(j.mode==="match"?"线路":"优选")+" "+j.created_text+"</span><span style='color:var(--dim)'>"+j.status+" · "+j.result_count+" 条</span>";
      d.onclick=()=>loadDetail(j.id);
      box.appendChild(d);
    }
  }catch(err){setStatus(String(err))}
}
async function loadDetail(id){
  try{
    const r=await fetch("/api/jobs/"+id); if(!r.ok)return;
    const j=await r.json();
    const table=$("result_table"); table.innerHTML="";
    const thead=document.createElement("thead"); const tr=document.createElement("tr");
    for(const h of j.headers){const th=document.createElement("th");th.textContent=h;tr.appendChild(th)}
    thead.appendChild(tr); table.appendChild(thead);
    const tbody=document.createElement("tbody");
    for(const row of j.results){
      const tr2=document.createElement("tr");
      for(const cell of row){const td=document.createElement("td");td.textContent=cell;tr2.appendChild(td)}
      tbody.appendChild(tr2);
    }
    table.appendChild(tbody);
    $("export_link").innerHTML='<a href="/api/jobs/'+id+'/export" download>导出 CSV</a>';
  }catch(err){setStatus(String(err))}
}
loadJobs();
</script>
</body>
</html>
"""
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, value, status=200):
        data = json.dumps(value, ensure_ascii=False).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.close_connection = True

    def send_html(self, html):
        data = html.encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.close_connection = True

    def do_GET(self):
        parts = urlparse(self.path).path.split("/")
        if self.path == "/":
            self.send_html(PAGE_HTML)
            return
        if self.path == "/api/jobs":
            with HISTORY_LOCK:
                summaries = [job_summary(job_id, JOBS[job_id])
                             for job_id in sorted(JOBS, key=lambda jid: JOBS[jid]["meta"].get("created", 0), reverse=True)]
            self.send_json({"jobs": summaries})
            return
        if len(parts) == 5 and parts[1:3] == ["api", "jobs"] and parts[4] == "events":
            self.handle_events(parts[3])
            return
        if len(parts) == 5 and parts[1:3] == ["api", "jobs"] and parts[4] == "export":
            self.handle_export(parts[3])
            return
        if len(parts) == 4 and parts[1:3] == ["api", "jobs"]:
            with HISTORY_LOCK:
                job = JOBS.get(parts[3])
            if job is None:
                self.send_json({"error": "任务不存在"}, 404)
            else:
                self.send_json(job_detail(parts[3], job))
            return
        self.send_json({"error": "未找到"}, 404)

    def handle_events(self, job_id):
        """SSE 实时事件流：长连接推送 JSON Lines 事件，job_done 后结束。"""
        with HISTORY_LOCK:
            job = JOBS.get(job_id)
            if job is not None:
                sent = job.get("event_offset", 0)
                events = job["events"]
        if job is None:
            self.send_json({"error": "任务不存在"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        last_flush = time.time()
        try:
            while True:
                with HISTORY_LOCK:
                    relative = max(0, sent - job.get("event_offset", 0))
                    batch = events[relative:]
                for event in batch:
                    self.wfile.write(("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode())
                    sent += 1
                if batch:
                    self.wfile.flush()
                    last_flush = time.time()
                with HISTORY_LOCK:
                    finished = bool(events) and events[-1].get("type") == "job_done"
                if finished:
                    break
                if time.time() - last_flush >= 15:
                    self.wfile.write(": ping\n\n".encode())
                    self.wfile.flush()
                    last_flush = time.time()
                time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def handle_export(self, job_id):
        with HISTORY_LOCK:
            job = JOBS.get(job_id)
        if job is None:
            self.send_json({"error": "任务不存在"}, 404)
            return
        detail = job_detail(job_id, job)
        query = parse_qs(urlparse(self.path).query)
        fmt = (query.get("fmt") or ["csv"])[0].lower()
        if fmt == "tsv":
            text = export_csv_text(detail["headers"], detail["all_results"], "\t")
            content_type = "text/tab-separated-values; charset=utf-8"
        else:
            text = "\ufeff" + export_csv_text(detail["headers"], detail["all_results"], ",")
            content_type = "text/csv; charset=utf-8"
        data = text.encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{job_id}.{fmt}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.close_connection = True

    def read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 2 * 1024 * 1024:
            raise ValueError("无效的请求体大小")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("无效的 JSON 请求体") from exc

    def do_POST(self):
        if self.path != "/api/jobs":
            self.send_json({"error": "未找到"}, 404)
            return
        try:
            payload = self.read_json_body()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        if not isinstance(payload, dict):
            self.send_json({"error": "无效的任务参数"}, 400)
            return
        mode = payload.get("mode", "match")
        if mode not in ("match", "optimize"):
            self.send_json({"error": "无效的任务类型"}, 400)
            return
        targets = payload.get("targets")
        if not isinstance(targets, list) or not targets:
            self.send_json({"error": "缺少目标/IP"}, 400)
            return
        targets = [str(target).strip() for target in targets]
        targets = [target for target in targets if target]
        if not targets:
            self.send_json({"error": "目标/IP 不能为空"}, 400)
            return
        if len(targets) > MODE_TARGET_LIMITS.get(mode, 100):
            self.send_json({"error": f"目标数量超出限制 ({MODE_TARGET_LIMITS[mode]})"}, 400)
            return
        payload["targets"] = targets
        job_id = launch_job(payload)
        self.send_json({"id": job_id, "ok": True})

    def do_DELETE(self):
        parts = urlparse(self.path).path.split("/")
        if len(parts) != 4 or parts[1:3] != ["api", "jobs"]:
            self.send_json({"error": "未找到"}, 404)
            return
        if not cancel_job(parts[3]):
            self.send_json({"error": "任务不存在"}, 404)
            return
        save_history()
        self.send_json({"ok": True})

    def log_message(self, *args):
        pass


class WebServer(ThreadingHTTPServer):
    # 关闭 SO_REUSEADDR：Windows 下该选项会放行对同一端口的重复绑定
    allow_reuse_address = False


def web_main(args):
    verify_backend()
    load_history()
    prune_history()
    save_history()
    try:
        server = WebServer(("127.0.0.1", args.port), Handler)
    except OSError:
        if args.port != 0:
            print(f"[-] 提示: 端口 {args.port} 被占用，改用随机端口", file=sys.stderr)
            server = WebServer(("127.0.0.1", 0), Handler)
        else:
            raise
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if not args.no_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def positive_int(value):
    try:
        number = int(value)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("必须为正整数") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("必须为正整数")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog="trace",
        description="线路探测 / 在线优选前端示例（CLI + Web 双界面，MIT 协议）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=("使用示例:\n"
                "  trace.py -t line -i ip.txt -o result.csv\n"
                "  trace.py -m web --port 51917\n"))
    parser.add_argument("-m", "--mode", choices=("cli", "web"), default="cli",
                        help="前端模式: cli（终端）/ web（本地 Web 控制台）")
    parser.add_argument("-t", "--task", choices=("line", "optimize"), default=None,
                        help="CLI 任务类型（不指定时交互选择，非交互默认线路探测）")
    parser.add_argument("-i", "--input", help="导入测试目标/IP 的文件 (*.txt / *.csv)")
    parser.add_argument("-o", "--output", default=None,
                        help="导出结果的文件 (默认: result.csv / result_optimize.csv)")
    parser.add_argument("-r", "--worker", metavar="WORKERS", type=positive_int,
                        default=None, help=f"线路探测并发 workers (默认 {DEFAULT_WORKER})")
    parser.add_argument("-mh", "--max-hops", metavar="MAX_HOPS", type=positive_int,
                        default=None, help=f"最大跳数 (默认 {DEFAULT_MAX_HOPS})")
    parser.add_argument("-f", "--filter-workers", metavar="WORKERS", type=positive_int,
                        default=None, help=f"数据筛选并发 workers (默认 {DEFAULT_FILTER_WORKERS})")
    parser.add_argument("-d", "--download-workers", metavar="WORKERS", type=positive_int,
                        default=None, help=f"下载测速并发 workers (默认 {DEFAULT_DOWNLOAD_WORKER})")
    parser.add_argument("-s", "--slim-workers", metavar="WORKERS", type=positive_int,
                        default=None, help=f"子网精简并发 workers (默认 {DEFAULT_SLIM_WORKERS})")
    parser.add_argument("-u", "--url", metavar="URL", default=None,
                        help="下载测速地址 (默认: 关闭; 例如: https://example.com/)")
    parser.add_argument("--latency-min", type=int, default=0, help="在线优选延迟下限 (ms)")
    parser.add_argument("--latency-max", type=int, default=999, help="在线优选延迟上限 (ms)")
    parser.add_argument("--subnet-sample", action="store_true", help="启用子网精简")
    parser.add_argument("--proxyip-check", action="store_true", help="启用 ProxyIP 检测")
    parser.add_argument("--risk-check", action="store_true", help="启用风险检测")
    parser.add_argument("--download-speed", action="store_true", help="启用下载测速")
    parser.add_argument("--port", type=int, default=51917, help="Web 模式监听端口 (默认 51917)")
    parser.add_argument("--no-browser", action="store_true", help="Web 模式不自动打开浏览器")
    return parser


def main():
    args = build_parser().parse_args()
    if args.mode == "web":
        web_main(args)
    else:
        cli_main(args)


if __name__ == "__main__":
    main()
