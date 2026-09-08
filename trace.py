""" 使用示例:
    py trace.py -i ip.txt -o result.csv
    py trace.py -m web --port 51917
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
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator, NoReturn
from urllib.parse import urlparse

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# 运行环境：Windows 控制台统一 UTF-8，避免中文乱码
# ---------------------------------------------------------------------------

def _force_utf8() -> None:
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
# 常量
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"          # 后端运行所需的数据库目录

TASK_TRACE = "line"                       # 线路探测（与 -t/--task 取值一致）
TASK_OPTIMIZE = "optimize"                # 在线优选

DEFAULT_WORKER = 15                       # 线路探测并发
DEFAULT_MAX_HOPS = 12                     # 线路探测最大跳数
DEFAULT_FILTER_WORKERS = 200              # 在线优选筛选并发
DEFAULT_DOWNLOAD_WORKERS = 5              # 在线优选下载测速并发
DEFAULT_SLIM_WORKERS = 32                 # 在线优选子网精简并发
DEFAULT_URL = "auto"                      # 下载测速地址

DISPLAY_COUNT = 10                        # 终端展示的结果条数
DETAIL_ROW_LIMIT = 500                    # Web 详情接口最多返回的行数
TARGET_LIMITS = {TASK_TRACE: 300, TASK_OPTIMIZE: 100_000}
MAX_REQUEST_BODY_BYTES = 1 << 20          # Web 请求体上限（1 MiB）
SSE_POLL_INTERVAL_SECONDS = 0.2           # SSE 轮询任务事件流的间隔

TRACE_HEADERS = ["IP地址", "ASN", "所属线路", "主机名", "运营商", "状态"]
OPTIMIZE_HEADERS = [
    "IP地址", "端口号", "TLS", "HTTP", "丢包率", "网络延迟", "下载速度",
    "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市",
    "ASN号码", "ASN组织", "ProxyIP", "风险等级",
]


# ---------------------------------------------------------------------------
# 后端定位
# ---------------------------------------------------------------------------

_BACKEND_CANDIDATES = (
    PROJECT_ROOT / "backend" / "main.exe",
)
_NEXTTRACE_CANDIDATES = (
    PROJECT_ROOT / "backend" / "nexttrace-core.exe",
    PROJECT_ROOT / "backend" / "nexttrace.exe",
)

BACKEND_EXECUTABLE = next(
    (str(path) for path in _BACKEND_CANDIDATES if path.is_file()),
    str(PROJECT_ROOT / "backend" / "main.exe"),
)
NEXTTRACE_EXECUTABLE = next(
    (str(path) for path in _NEXTTRACE_CANDIDATES if path.is_file()),
    str(PROJECT_ROOT / "backend" / "nexttrace-core.exe"),
)


def _fail(message: str) -> NoReturn:
    """打印错误并退出进程（CLI 辅助函数）。"""
    print(f"[-] {message}", file=sys.stderr)
    sys.exit(1)


def ensure_backend_available() -> None:
    """启动前检查后端与 nexttrace-core 是否存在。"""
    if not os.path.isfile(BACKEND_EXECUTABLE):
        _fail("未找到 main.exe，请先构建后端: "
              "cd backend && go build -o main.exe .")
    if not os.path.isfile(NEXTTRACE_EXECUTABLE):
        _fail("未找到 nexttrace-core.exe / nexttrace.exe，"
              "请将其放到 backend 目录")


# ---------------------------------------------------------------------------
# 目标解析
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_IP_PART = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)"
_CIDR_RE = re.compile(_IP_PART + r"/\d{1,3}")
_RANGE_RE = re.compile(_IP_PART + r"\s*-\s*" + _IP_PART)
_TARGET_TOKEN_RE = re.compile(
    r"\[[0-9A-Fa-f:.]+\](?::\d+)?"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"
    r"|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])*)+(?::\d+)?")
_BARE_IPV6_RE = re.compile(r"[0-9A-Fa-f:]+")


def _raise_target(message: str) -> NoReturn:
    raise ValueError(message)


def _validate_target_token(token: str, line_number: int) -> str:
    """校验单个目标 token：显式端口与字面 IPv4/IPv6 在此拦截。"""
    host, port = token, None
    if token.startswith("["):
        end = token.find("]")
        if end < 0:
            _raise_target(f"第 {line_number} 行方括号不完整: '{token}'")
        host = token[1:end]
        rest = token[end + 1:]
        if rest:
            if not rest.startswith(":"):
                _raise_target(f"第 {line_number} 行方括号后只支持端口: '{token}'")
            port = rest[1:]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            _raise_target(f"第 {line_number} 行不是有效的方括号 IPv6: '{token}'")
        if address.version != 6:
            _raise_target(f"第 {line_number} 行方括号语法仅支持 IPv6: '{token}'")
    elif token.count(":") == 1:
        host, _, port = token.rpartition(":")
    if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
        _raise_target(f"第 {line_number} 行端口必须为 1-65535: '{token}'")
    if "." in host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if _IPV4_RE.fullmatch(host):
                _raise_target(f"第 {line_number} 行不是有效 IPv4: '{token}'")
    return token


def _extract_target_token(raw_line: str, line_number: int) -> str | None:
    """把一行输入解析为单个目标；注释（'#' 后）与空行返回 None。

    支持 [IPv6]:port / 裸 IPv6(:port) / IPv4(:port) / 域名(:port)。
    """
    content = raw_line.split("#", 1)[0].strip()
    if not content:
        return None
    if re.search(r"\s", content):
        _raise_target(f"第 {line_number} 行包含空白，每行只能有一个目标: '{content}'")

    tokens = _TARGET_TOKEN_RE.findall(content)
    if len(tokens) == 1 and tokens[0] == content:
        return _validate_target_token(content, line_number)

    # 裸 IPv6 的尾部数字组优先按端口剥离，否则按完整 IPv6 处理。
    if content.count(":") >= 2 and "[" not in content and _BARE_IPV6_RE.fullmatch(content):
        candidate, _, port_text = content.rpartition(":")
        if port_text.isdigit() and len(port_text) <= 5:
            try:
                ipaddress.ip_address(candidate)
                if 1 <= int(port_text) <= 65535:
                    return _validate_target_token(candidate, line_number)
                _raise_target(f"第 {line_number} 行端口必须为 1-65535: '{content}'")
            except ValueError:
                pass
        try:
            ipaddress.ip_address(content)
            return _validate_target_token(content, line_number)
        except ValueError:
            pass

    hint = ("（支持裸 IPv6 或方括号写法，如 2606:4700:: / [2606:4700::]）"
            if content.count(":") > 1 else "")
    _raise_target(f"第 {line_number} 行不是有效的单个目标/IP: '{content}'{hint}")


def _parse_optimize_token(raw_line: str, line_number: int) -> str | None:
    """在线优选输入：单目标之外放行 CIDR 与 IP 区间。"""
    content = raw_line.split("#", 1)[0].strip()
    if not content:
        return None
    if _CIDR_RE.fullmatch(content) or _RANGE_RE.fullmatch(content):
        return content
    return _extract_target_token(raw_line, line_number)


def estimate_expand_count(tokens: list[object], limit: int) -> int:
    """估算在线优选展开后的地址总数，CIDR/IP 区间先合并去重再计数。"""
    spans_v4: list[tuple[int, int]] = []
    spans_v6: list[tuple[int, int]] = []
    total = 0

    def merge_spans(spans: list[tuple[int, int]]) -> int:
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

    for raw_token in tokens:
        token = str(raw_token or "").strip()
        if not token:
            continue
        if _CIDR_RE.fullmatch(token):
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise ValueError(f"无效 CIDR: {token}") from None
            span = (int(network.network_address), int(network.broadcast_address))
            (spans_v4 if network.version == 4 else spans_v6).append(span)
        elif _RANGE_RE.fullmatch(token):
            start_text, _, end_text = token.partition("-")
            try:
                start = ipaddress.ip_address(start_text.strip())
            except ValueError:
                raise ValueError(f"无效 IP 区间: {token}") from None
            try:
                end = ipaddress.ip_address(end_text.strip())
            except ValueError:
                raise ValueError(f"无效 IP 区间: {token}") from None
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


def _finalize_targets(task: str, tokens: list[str]) -> list[str]:
    """按任务类型检查目标规模；线路探测超限时截断，优选超限时报错。"""
    if not tokens:
        return []
    limit = TARGET_LIMITS[task]
    if task == TASK_OPTIMIZE:
        estimate_expand_count(tokens, limit)
    elif len(tokens) > limit:
        print(f"[+] 线路探测: 候选超过单次上限{limit}条，仅检测前 {limit} 条")
        tokens = tokens[:limit]
    return tokens


def read_targets(path: str, *, task: str = TASK_TRACE) -> list[str]:
    """读取目标列表；线路探测拒绝 CIDR/区间，在线优选支持展开估算。"""
    tokens: list[str] = []
    try:
        with open(path, encoding="utf-8-sig", errors="ignore") as file:
            for line_number, raw_line in enumerate(file, 1):
                parser = (_parse_optimize_token if task == TASK_OPTIMIZE
                          else _extract_target_token)
                token = parser(raw_line, line_number)
                if token:
                    tokens.append(token)
    except OSError as exc:
        raise RuntimeError(f"无法读取文件 '{path}': {exc}") from exc
    return _finalize_targets(task, tokens)


def validate_targets(task: str, values: list[object]) -> list[str]:
    """校验 Web 提交的目标数组，并复用与 CLI 相同的上限规则。"""
    tokens: list[str] = []
    for index, raw in enumerate(values, 1):
        if task == TASK_OPTIMIZE:
            token = _parse_optimize_token(str(raw), index)
        else:
            token = _extract_target_token(str(raw), index)
        if token:
            tokens.append(token)
    return _finalize_targets(task, tokens)


# ---------------------------------------------------------------------------
# 任务参数与命令构建
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TraceOptions:
    """线路探测任务参数。"""
    worker: int = DEFAULT_WORKER
    max_hops: int = DEFAULT_MAX_HOPS


@dataclass(frozen=True)
class OptimizeOptions:
    """在线优选任务参数。"""
    filter_workers: int = DEFAULT_FILTER_WORKERS
    download_workers: int = DEFAULT_DOWNLOAD_WORKERS
    latency_min: int = 0
    latency_max: int = 999
    download_speed: bool = False
    url: str = DEFAULT_URL
    subnet_sample: bool = False
    slim_workers: int = DEFAULT_SLIM_WORKERS
    proxyip_check: bool = False
    risk_check: bool = False


@contextlib.contextmanager
def temporary_input_file(targets: list[str]) -> Iterator[str]:
    """把目标写入临时输入文件，供后端读取；离开上下文时自动清理。"""
    fd, path = tempfile.mkstemp(prefix="trace_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        for target in targets:
            file.write(json.dumps({"token": target}, ensure_ascii=False) + "\n")
    try:
        yield path
    finally:
        os.unlink(path)


def _decode_backend_output(raw: bytes) -> str:
    """解码后端输出：优先 UTF-8，兜底 gb18030（旧版 Windows 控制台）。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gb18030", errors="replace")


class TraceBackend:
    """本地后端 ``main.exe`` 的子进程适配器。

    后端负责线路探测与在线优选的网络执行，并以 JSON Lines 输出事件；本类负责
    命令组装、子进程生命周期管理和事件流解码。任何一条运行路径都必须经过此
    适配器，因此缺少 ``main.exe`` 时任务会明确失败。
    """

    def trace(self, input_path: str, options: TraceOptions) -> Iterator[dict]:
        return self._run([
            BACKEND_EXECUTABLE, "-nexttrace", "-i", input_path, "-input-json=true",
            "-r", str(options.worker), "-max-hops", str(options.max_hops),
        ])

    def optimize(self, input_path: str, options: OptimizeOptions) -> Iterator[dict]:
        command = [
            BACKEND_EXECUTABLE, "-optimize-probe", "-i", input_path, "-input-json=true",
            "-f", str(options.filter_workers),
            "-download-workers", str(options.download_workers),
            "-latency-min", str(options.latency_min),
            "-latency-max", str(options.latency_max),
        ]
        if options.subnet_sample:
            command += ["-s", str(options.slim_workers)]
        if options.proxyip_check:
            command += ["-proxyip-check=true"]
        if options.risk_check:
            command += ["-risk-check=true"]
        if options.download_speed:
            command += ["-url", options.url or DEFAULT_URL]
        return self._run(command)

    def _run(self, command: list[str]) -> Iterator[dict]:
        """启动 ``main.exe`` 并逐条返回 JSON 事件。"""
        env = os.environ.copy()
        env["TRACE_DATA_DIR"] = str(DATA_DIR)
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as exc:
            raise RuntimeError(f"无法启动 main.exe: {exc}") from exc

        stderr_chunks: list[str] = []

        def drain_stderr() -> None:
            for raw_line in process.stderr:
                stderr_chunks.append(_decode_backend_output(raw_line))

        threading.Thread(target=drain_stderr, daemon=True).start()
        try:
            for raw_line in process.stdout:
                line = _decode_backend_output(raw_line).strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield {"type": "log", "message": line}
        finally:
            exit_code = process.wait()
            for stream in (process.stdout, process.stderr):
                stream.close()
            if exit_code != 0:
                detail = "".join(stderr_chunks).strip()
                raise RuntimeError(f"main.exe 异常退出 (code={exit_code}): {detail[:200]}")


# ---------------------------------------------------------------------------
# 结果整理
# ---------------------------------------------------------------------------

def format_ip_for_display(value: object) -> str:
    """IPv6 用方括号包裹展示（如 [2606:4700::1]）。"""
    text = str(value or "")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    return f"[{text}]" if address.version == 6 else text


def trace_event_to_row(event: dict) -> list[str]:
    """把后端 result 事件整理为表格行：[IP, ASN, 线路, 主机名, 运营商, 状态]。"""
    def clean_field(key: str) -> str:
        value = str(event.get(key) or "").strip()
        return "error" if not value or value.lower() == "none" else value

    fields = [clean_field("matched_asn"), clean_field("line_type"),
              clean_field("hostname"), clean_field("isp")]
    status = "失败" if event.get("error") or "error" in fields else "成功"
    return [format_ip_for_display(event.get("target", "")), *fields, status]


def result_row_for_event(mode: str, event: dict) -> list | None:
    """按任务类型从事件中提取一条结果行；非结果事件返回 None。"""
    if mode == TASK_TRACE:
        return trace_event_to_row(event) if event.get("type") == "result" else None
    if event.get("type") != "opt_record" or not event.get("display", True):
        return None
    record = event.get("record") or {}
    return list(event.get("row") or []) if record.get("qualified") else None


# ---------------------------------------------------------------------------
# 结果导出
# ---------------------------------------------------------------------------

def _fill_csv(writer, headers: list[str], rows: list[list]) -> None:
    writer.writerow(headers)
    writer.writerows(rows)


def render_csv_text(headers: list[str], rows: list[list], delimiter: str = ",") -> str:
    """把表格转为 CSV 文本（Web 导出用）。"""
    buffer = io.StringIO()
    _fill_csv(csv.writer(buffer, delimiter=delimiter), headers, rows)
    return buffer.getvalue()


def export_rows(headers: list[str], rows: list[list], output_path: str) -> None:
    """写出结果文件：.txt 用制表符（TSV），其余用逗号（CSV）。

    先写临时文件再原子替换，避免导出中断留下半个文件。
    """
    delimiter = "\t" if output_path.lower().endswith(".txt") else ","
    final_path = os.path.abspath(output_path)
    fd, tmp_path = tempfile.mkstemp(prefix=".trace_", suffix=".tmp",
                                    dir=os.path.dirname(final_path) or os.curdir)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8-sig") as file:
            _fill_csv(csv.writer(file, delimiter=delimiter), headers, rows)
        os.replace(tmp_path, final_path)
    except BaseException:
        os.unlink(tmp_path)
        raise
    print(f"[+] 已导出 {len(rows)} 行 -> {output_path}")


# ---------------------------------------------------------------------------
# CLI 前端
# ---------------------------------------------------------------------------

def run_trace_task(targets: list[str], options: TraceOptions,
                   backend: TraceBackend) -> list[list]:
    """线路探测：写输入 -> 读事件流 -> 收集结果行。"""
    total = len(targets)
    rows: list[list] = []
    with temporary_input_file(targets) as input_path:
        for event in backend.trace(input_path, options):
            row = result_row_for_event(TASK_TRACE, event)
            if row is not None:
                rows.append(row)
                print(f"\r[线路探测] 完成 {len(rows)}/{total}", end="", flush=True)
    print()
    return rows


def run_optimize_task(targets: list[str], options: OptimizeOptions,
                      backend: TraceBackend) -> list[list]:
    """在线优选：写输入 -> 读事件流 -> 收集合格结果行。"""
    rows: list[list] = []
    with temporary_input_file(targets) as input_path:
        for event in backend.optimize(input_path, options):
            if event.get("type") == "opt_stage":
                print(f"[优选] 阶段 {event.get('phase')}: {event.get('status')}")
                continue
            row = result_row_for_event(TASK_OPTIMIZE, event)
            if row is not None:
                rows.append(row)
    return rows


def check_mode_params(args: argparse.Namespace) -> None:
    """拒绝把线路探测与在线优选各自的专属参数混用。"""
    if args.task == TASK_TRACE:
        conflicts = [name for name, value in (
            ("-u/--url", args.url),
            ("-f/--filter", args.filter_workers),
            ("-d/--download", args.download_workers),
            ("-s/--slim", args.slim_workers),
        ) if value is not None]
        scope = "在线优选"
    else:
        conflicts = [name for name, value in (
            ("-r/--worker", args.worker),
            ("-mh/--max-hops", args.max_hops),
        ) if value is not None]
        scope = "线路探测"
    if conflicts:
        _fail(f"参数 {', '.join(conflicts)} 仅适用于{scope}模式")

def show_top_results(rows: list[list], limit: int = DISPLAY_COUNT) -> None:
    """在终端展示前 limit 条结果（后端已完成排序）。"""
    print("-" * 60)
    print(f"[+] 结果 TOP{min(limit, len(rows))}:")
    for row in rows[:limit]:
        print("  ".join(str(cell) for cell in row))


def cli_main(args: argparse.Namespace) -> None:
    """CLI 入口：读取目标 -> 执行任务 -> 展示并导出结果。"""
    ensure_backend_available()
    check_mode_params(args)
    backend = TraceBackend()
    if not args.input:
        _fail("缺少输入文件，请使用 -i 指定目标文件")
    try:
        targets = read_targets(args.input, task=args.task)
    except (RuntimeError, ValueError) as exc:
        _fail(f"错误: {exc}")
    if not targets:
        _fail("输入文件中没有有效目标")
    if len(targets) > TARGET_LIMITS[args.task]:
        _fail(f"目标数量超出限制 ({TARGET_LIMITS[args.task]})")
    print(f"[+] 已读取目标: {len(targets)} 条")

    try:
        if args.task == TASK_TRACE:
            options = TraceOptions(worker=args.worker or DEFAULT_WORKER,
                                   max_hops=args.max_hops or DEFAULT_MAX_HOPS)
            rows = run_trace_task(targets, options, backend)
            headers, default_output = TRACE_HEADERS, "result.csv"
        else:
            options = OptimizeOptions(
                filter_workers=args.filter_workers or DEFAULT_FILTER_WORKERS,
                download_workers=args.download_workers or DEFAULT_DOWNLOAD_WORKERS,
                download_speed=args.download_speed,
                url=args.url or DEFAULT_URL,
                subnet_sample=args.slim_workers is not None,
                slim_workers=args.slim_workers or DEFAULT_SLIM_WORKERS,
                proxyip_check=args.proxyip_check,
                risk_check=args.risk_check)
            rows = run_optimize_task(targets, options, backend)
            headers, default_output = OPTIMIZE_HEADERS, "result_optimize.csv"
    except RuntimeError as exc:
        _fail(f"错误: {exc}")
    show_top_results(rows)
    export_rows(headers, rows, args.output or default_output)


# ---------------------------------------------------------------------------
# Web 前端：任务管理
# ---------------------------------------------------------------------------

@dataclass
class Job:
    """单个 Web 任务的运行状态（读写均需持有 JOBS_LOCK）。"""
    mode: str
    target_count: int
    created_at: float
    status: str = "running"                          # running -> done / failed
    result_count: int = 0
    events: list[dict] = field(default_factory=list)  # SSE 推送的事件源
    rows: list[list] = field(default_factory=list)    # 详情与导出的数据源


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()
BACKEND = TraceBackend()


def start_job(request: dict) -> str:
    """创建任务并启动后台线程消费事件流，立即返回 job_id。"""
    job_id = os.urandom(8).hex()
    job = Job(mode=request.get("mode", TASK_TRACE),
              target_count=len(request["targets"]),
              created_at=time.time())
    with JOBS_LOCK:
        JOBS[job_id] = job
    threading.Thread(target=_run_job, args=(job, request, BACKEND),
                     daemon=True).start()
    return job_id


def _run_job(job: Job, request: dict, backend: TraceBackend) -> None:
    """后台线程：与 CLI 共用事件流消费，把事件与结果行写入任务表。"""
    failure_reason = None
    try:
        with temporary_input_file(request["targets"]) as input_path:
            if job.mode == TASK_TRACE:
                options = TraceOptions(request.get("worker", DEFAULT_WORKER),
                                       request.get("max_hops", DEFAULT_MAX_HOPS))
                events = backend.trace(input_path, options)
            else:
                options = OptimizeOptions(
                    filter_workers=request.get("filter_workers", DEFAULT_FILTER_WORKERS),
                    download_workers=request.get("download_workers", DEFAULT_DOWNLOAD_WORKERS),
                    download_speed=bool(request.get("download_speed")),
                    url=request.get("url") or DEFAULT_URL,
                    subnet_sample=bool(request.get("subnet_sample")),
                    slim_workers=request.get("slim_workers", DEFAULT_SLIM_WORKERS),
                    proxyip_check=bool(request.get("proxyip_check")),
                    risk_check=bool(request.get("risk_check")))
                events = backend.optimize(input_path, options)
            for event in events:
                with JOBS_LOCK:
                    job.events.append(event)
                    row = result_row_for_event(job.mode, event)
                    if row is not None:
                        job.rows.append(row)
                        # 线路探测只把「成功」计入 result_count；优选全部计数
                        if job.mode != TASK_TRACE or row[-1] == "成功":
                            job.result_count += 1
    except Exception as exc:            # 捕获后任务标记失败，事件流照常结束
        failure_reason = str(exc)
    with JOBS_LOCK:
        job.status = "failed" if failure_reason else "done"
        job.events.append({"type": "job_done",
                           "error": failure_reason is not None,
                           "message": failure_reason})


def job_summary(job_id: str, job: Job) -> dict:
    """任务列表页使用的摘要视图。"""
    return {"id": job_id,
            "mode": job.mode,
            "status": job.status,
            "result_count": job.result_count,
            "target_count": job.target_count,
            "created_text": time.strftime("%m-%d %H:%M", time.localtime(job.created_at))}


def job_detail(job_id: str, job: Job) -> dict:
    """任务详情页视图：表头 + 截断后的结果行。"""
    headers = TRACE_HEADERS if job.mode == TASK_TRACE else OPTIMIZE_HEADERS
    return {"headers": headers, "rows": job.rows[:DETAIL_ROW_LIMIT],
            **job_summary(job_id, job)}


# ---------------------------------------------------------------------------
# Web 前端：HTTP 服务
# ---------------------------------------------------------------------------

class TraceRequestHandler(BaseHTTPRequestHandler):
    """本地控制台 HTTP 服务：页面、任务 API 与 SSE 推送。"""

    protocol_version = "HTTP/1.1"

    def _respond(self, content_type: str, body: bytes, status: int = 200,
                 extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value: object, status: int = 200) -> None:
        self._respond("application/json; charset=utf-8",
                      json.dumps(value, ensure_ascii=False).encode(), status)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._respond("text/html; charset=utf-8", INDEX_PAGE_HTML.encode())
        elif path == "/api/jobs":
            with JOBS_LOCK:
                summaries = [job_summary(job_id, job) for job_id, job in JOBS.items()]
            self.send_json({"jobs": summaries})
        elif path.startswith("/api/jobs/"):
            self._handle_job_route(path)
        else:
            self.send_json({"error": "未找到"}, 404)

    def _handle_job_route(self, path: str) -> None:
        """处理 /api/jobs/<job_id>[/(events|export)]。"""
        segments = path.split("/")          # ['', 'api', 'jobs', <job_id>, ...]
        with JOBS_LOCK:
            job = JOBS.get(segments[3])
        if job is None:
            self.send_json({"error": "任务不存在"}, 404)
        elif len(segments) == 4:
            with JOBS_LOCK:                 # 快照在锁内构建，响应在锁外发送
                detail = job_detail(segments[3], job)
            self.send_json(detail)
        elif segments[4] == "events":
            self._stream_events(job)
        elif segments[4] == "export":
            self._send_export_csv(segments[3], job)
        else:
            self.send_json({"error": "未找到"}, 404)

    def do_POST(self):
        if self.path != "/api/jobs":
            self.send_json({"error": "未找到"}, 404)
            return
        request = self._read_json_body()
        if request is None:
            return
        error = _validate_job_request(request)
        if error:
            self.send_json({"error": error}, 400)
            return
        self.send_json({"id": start_job(request), "ok": True})

    def _read_json_body(self) -> dict | None:
        """读取并解析 JSON 请求体；失败时直接回 400 并返回 None。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_REQUEST_BODY_BYTES:
            self.send_json({"error": "请求体过大或为空"}, 400)
            return None
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_json({"error": "无效的 JSON 请求体"}, 400)
            return None
        if not isinstance(request, dict):
            self.send_json({"error": "参数无效: 需要 mode 与 targets"}, 400)
            return None
        return request

    def _stream_events(self, job: Job) -> None:
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
                    batch = job.events[sent:]
                for event in batch:
                    self.wfile.write(
                        ("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode())
                    sent += 1
                if batch:
                    self.wfile.flush()
                    if batch[-1].get("type") == "job_done":
                        break
                time.sleep(SSE_POLL_INTERVAL_SECONDS)
        except OSError:                     # 浏览器断开连接
            return

    def _send_export_csv(self, job_id: str, job: Job) -> None:
        headers = TRACE_HEADERS if job.mode == TASK_TRACE else OPTIMIZE_HEADERS
        with JOBS_LOCK:
            rows = list(job.rows)
        data = ("\ufeff" + render_csv_text(headers, rows)).encode()   # BOM 兼容 Excel
        self._respond("text/csv; charset=utf-8", data,
                      extra_headers={"Content-Disposition":
                                     f'attachment; filename="{job_id}.csv"'})

    def log_message(self, *args):
        pass    # 关闭默认请求日志


def _validate_job_request(request: dict) -> str | None:
    """校验并规范化创建任务请求；返回错误消息，通过时返回 None。"""
    mode = request.get("mode", TASK_TRACE)
    targets = request.get("targets")
    if mode not in (TASK_TRACE, TASK_OPTIMIZE) or not isinstance(targets, list) or not targets:
        return "参数无效: 需要 mode 与 targets"
    cleaned = [str(target).strip() for target in targets if str(target).strip()]
    if not cleaned:
        return "参数无效: 需要 mode 与 targets"
    if len(cleaned) > TARGET_LIMITS[mode]:
        return f"目标数量超出限制 ({TARGET_LIMITS[mode]})"
    request["targets"] = cleaned
    return None


def web_main(args: argparse.Namespace) -> None:
    """Web 入口：启动本地 HTTP 服务并（可选）打开浏览器。"""
    ensure_backend_available()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), TraceRequestHandler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if not args.no_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


INDEX_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trace（线路探测 / 在线优选）</title>
<style>
:root{
  --bg:#f4f6f8; --card:#fff; --border:#e5e8ec; --text:#1f2329; --muted:#8a93a1;
  --primary:#2f6bff; --primary-dark:#1d4fd7; --green:#18a058; --red:#e5484d;
  --radius:10px; --mono:Consolas,"JetBrains Mono",monospace;
}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);
     font:14px/1.6 system-ui,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:1080px;margin:0 auto;display:grid;gap:16px}
h1{margin:0;font-size:22px}
.subtitle{margin:2px 0 18px;color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
      padding:16px 18px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card h2{margin:0 0 12px;font-size:15px;display:flex;align-items:center;gap:10px}
label{font-size:12px;color:var(--muted)}
input,select,textarea{border:1px solid var(--border);border-radius:6px;padding:6px 8px;
     font:inherit;color:var(--text);background:#fff}
input:focus,select:focus,textarea:focus{outline:2px solid #c7d8ff;border-color:var(--primary)}
input[type=number]{width:96px}
.toolbar{display:flex;flex-wrap:wrap;gap:12px 16px;align-items:flex-end;margin-bottom:10px}
.field{display:flex;flex-direction:column;gap:4px}
.range{display:flex;align-items:center;gap:6px}
.range input{width:78px}
.check{display:flex;align-items:center;gap:6px;padding-bottom:7px;cursor:pointer;color:var(--text)}
textarea{width:100%;min-height:110px;font-family:var(--mono);font-size:13px;margin-top:4px}
.actions{display:flex;align-items:center;gap:12px;margin-top:10px}
button{border:1px solid var(--border);background:#fff;border-radius:6px;padding:6px 14px;
       cursor:pointer;font:inherit}
button.primary{background:var(--primary);border-color:var(--primary);color:#fff}
button.primary:hover{background:var(--primary-dark)}
button.ghost{padding:2px 10px;font-size:12px}
#hint{font-size:13px;color:var(--muted)}
#hint.err{color:var(--red)}
.progress-row{display:flex;align-items:center;gap:10px;margin-top:12px}
.progress-row.hidden,.hidden{display:none}
.progress{flex:1;height:6px;background:#e9edf2;border-radius:4px;overflow:hidden}
#progress_bar{height:100%;width:0;background:var(--primary);transition:width .2s}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid var(--border);padding:6px 10px;text-align:left;white-space:nowrap}
th{color:var(--muted);font-weight:600;background:#fafbfc;position:sticky;top:0}
.table-wrap{overflow:auto;max-height:380px;border:1px solid var(--border);border-radius:8px}
#jobs tr{cursor:pointer}
#jobs tr:hover{background:#f6f8fa}
#jobs tr.active{background:#f0f5ff}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;
       background:#eef1f4;color:var(--muted)}
.badge.running{background:#e8efff;color:var(--primary)}
.badge.done{background:#e6f6ec;color:var(--green)}
.badge.failed{background:#fdebec;color:var(--red)}
.mono{font-family:var(--mono)}
.muted{color:var(--muted);font-weight:400;font-size:12px}
.empty{color:var(--muted);text-align:center}
.ok{color:var(--green)}
.bad{color:var(--red)}
#events{height:170px;overflow:auto;background:#0f172a;color:#cbd5e1;border-radius:8px;
        padding:10px 12px;font:12px/1.6 var(--mono);white-space:pre-wrap;word-break:break-all}
</style>
</head>
<body>
<main>
  <header>
    <h1>Trace</h1>
    <p class="subtitle">线路探测 / 在线优选</p>
  </header>

  <section class="card">
    <h2>新建任务</h2>
    <div class="toolbar">
      <div class="field">
        <label for="mode">任务类型</label>
        <select id="mode" onchange="syncForm()">
          <option value="line">线路探测</option>
          <option value="optimize">在线优选</option>
        </select>
      </div>
      <div class="field trace-only">
        <label for="worker">并发</label>
        <input id="worker" type="number" min="1" value="15">
      </div>
      <div class="field trace-only">
        <label for="max_hops">最大跳数</label>
        <input id="max_hops" type="number" min="1" value="12">
      </div>
      <div class="field optimize-only">
        <label for="filter_workers">筛选并发</label>
        <input id="filter_workers" type="number" min="1" value="200">
      </div>
      <div class="field optimize-only">
        <label for="download_workers">测速并发</label>
        <input id="download_workers" type="number" min="1" value="5">
      </div>
      <div class="field optimize-only">
        <label for="slim_workers">子网精简并发</label>
        <input id="slim_workers" type="number" min="1" value="0">
      </div>
      <div class="field optimize-only">
        <label for="url">测速地址</label>
        <input id="url" placeholder="auto">
      </div>
      <label class="check optimize-only">
        <input id="download_speed" type="checkbox"> 下载测速
      </label>
      <label class="check optimize-only">
        <input id="proxyip_check" type="checkbox"> ProxyIP 检测
      </label>
      <label class="check optimize-only">
        <input id="risk_check" type="checkbox"> 风险检测
      </label>
    </div>
    <label for="targets">目标（每行一个：IP / 域名[:端口] / CIDR / IP 区间）</label>
    <textarea id="targets" placeholder="1.1.1.1&#10;example.com:443&#10;104.16.0.0/24"></textarea>
    <div class="actions">
      <button class="primary" onclick="startJob()">开始任务</button>
      <button onclick="refreshJobs()">刷新任务</button>
      <span id="hint"></span>
    </div>
    <div class="progress-row hidden" id="progress_wrap">
      <div class="progress"><div id="progress_bar"></div></div>
      <span id="progress_text" class="muted"></span>
    </div>
  </section>

  <section class="card">
    <h2>任务列表</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>任务</th><th>模式</th><th>状态</th><th>结果</th><th>时间</th></tr></thead>
        <tbody id="jobs"></tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>结果 <a id="export" class="hidden" href="#">导出 CSV</a></h2>
    <div class="table-wrap"><table id="result"></table></div>
  </section>

  <section class="card">
    <h2>实时事件 <span id="stage" class="muted"></span></h2>
    <div id="events"></div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const MODE_TEXT = { line: "线路探测", optimize: "在线优选" };
const STATUS_TEXT = { running: "运行中", done: "已完成", failed: "失败" };
let currentJob = null, eventSource = null;
let progressDone = 0, progressTotal = 0;

function syncForm() {
  const optimize = $("mode").value === "optimize";
  document.querySelectorAll(".trace-only").forEach(el => el.style.display = optimize ? "none" : "");
  document.querySelectorAll(".optimize-only").forEach(el => el.style.display = optimize ? "" : "none");
}

function hint(text, isError = false) {
  const el = $("hint");
  el.textContent = text;
  el.className = isError ? "err" : "";
}

function setProgress(done, total) {
  progressDone = done;
  progressTotal = total;
  const wrap = $("progress_wrap");
  if (!total) { wrap.classList.add("hidden"); return; }
  wrap.classList.remove("hidden");
  $("progress_bar").style.width = Math.min(100, done * 100 / total) + "%";
  $("progress_text").textContent = done + "/" + total;
}

async function startJob() {
  const targets = $("targets").value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!targets.length) return hint("请先输入目标", true);
  const payload = { mode: $("mode").value, targets };
  if (payload.mode === "line") {
    payload.worker = +$("worker").value || 15;
    payload.max_hops = +$("max_hops").value || 12;
  } else {
    payload.filter_workers = +$("filter_workers").value || 200;
    payload.download_workers = +$("download_workers").value || 5;
    payload.download_speed = $("download_speed").checked;
    payload.url = $("url").value.trim() || "auto";
    payload.slim_workers = +$("slim_workers").value || 0;
    payload.subnet_sample = payload.slim_workers > 0;
    payload.proxyip_check = $("proxyip_check").checked;
    payload.risk_check = $("risk_check").checked;
  }
  try {
    const r = await fetch("/api/jobs", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (!r.ok) return hint(data.error || "创建失败", true);
    hint("任务已启动");
    $("events").innerHTML = "";
    $("stage").textContent = "";
    $("export").classList.add("hidden");
    progressDone = 0;
    progressTotal = 0;
    setProgress(0, payload.mode === "line" ? targets.length : 0);
    follow(data.id);
    refreshJobs();
  } catch {
    hint("无法连接服务", true);
  }
}

function follow(jobId) {
  if (eventSource) eventSource.close();
  currentJob = jobId;
  progressDone = 0;
  progressTotal = 0;
  eventSource = new EventSource("/api/jobs/" + jobId + "/events");
  eventSource.onmessage = m => handleEvent(JSON.parse(m.data));
}

function handleEvent(e) {
  if (e.type === "job_done") {
    eventSource.close();
    eventSource = null;
    hint(e.error ? "任务失败" : "任务完成", e.error);
    refreshJobs();
    loadDetail(currentJob);
    return;
  }
  if (e.type === "result" && progressTotal) setProgress(progressDone + 1, progressTotal);
  if (e.type === "opt_stage") $("stage").textContent = "阶段 " + (e.phase ?? "") + "：" + (e.status ?? "");
  appendEvent(e);
}

function appendEvent(e) {
  const box = $("events");
  const line = document.createElement("div");
  line.textContent = e.type + "  " + JSON.stringify(e).slice(0, 240);
  box.appendChild(line);
  while (box.childElementCount > 300) box.firstChild.remove();
  box.scrollTop = box.scrollHeight;
}

function addCell(tr, text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  tr.appendChild(td);
  return td;
}

async function refreshJobs() {
  try {
    const data = await (await fetch("/api/jobs")).json();
    const tbody = $("jobs");
    tbody.innerHTML = "";
    if (!data.jobs.length) {
      addCell(tbody.appendChild(document.createElement("tr")), "暂无任务", "empty").colSpan = 5;
      return;
    }
    for (const j of data.jobs) {
      const tr = document.createElement("tr");
      if (j.id === currentJob) tr.className = "active";
      tr.onclick = () => loadDetail(j.id);
      addCell(tr, j.id.slice(0, 8), "mono");
      addCell(tr, MODE_TEXT[j.mode] || j.mode);
      const statusCell = document.createElement("td");
      const badge = document.createElement("span");
      badge.textContent = STATUS_TEXT[j.status] || j.status;
      badge.className = "badge " + j.status;
      statusCell.appendChild(badge);
      tr.appendChild(statusCell);
      addCell(tr, j.result_count + " / " + j.target_count);
      addCell(tr, j.created_text);
      tbody.appendChild(tr);
    }
  } catch { /* 服务临时不可达，等下一轮轮询 */ }
}

async function loadDetail(jobId) {
  currentJob = jobId;
  const r = await fetch("/api/jobs/" + jobId);
  if (!r.ok) return hint("任务不存在", true);
  const j = await r.json();
  const table = $("result");
  table.innerHTML = "";
  const head = document.createElement("tr");
  for (const name of j.headers) {
    const th = document.createElement("th");
    th.textContent = name;
    head.appendChild(th);
  }
  table.appendChild(head);
  const body = document.createElement("tbody");
  for (const row of j.rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const td = document.createElement("td");
      td.textContent = value;
      if (value === "成功") td.className = "ok";
      else if (value === "失败" || value === "error") td.className = "bad";
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
  const link = $("export");
  link.href = "/api/jobs/" + jobId + "/export";
  link.classList.remove("hidden");
}

syncForm();
refreshJobs();
setInterval(refreshJobs, 5000);
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
    parser.add_argument("-t", "--task", choices=(TASK_TRACE, TASK_OPTIMIZE), default=TASK_TRACE,
                        help="任务类型: 线路探测 / 在线优选")
    parser.add_argument("-i", "--input", help="目标/IP 文件（每行一个）")
    parser.add_argument("-o", "--output", help="结果文件（默认 result.csv / result_optimize.csv）")
    parser.add_argument("-r", "--worker", type=_positive_int, help=f"线路探测并发（默认 {DEFAULT_WORKER}）")
    parser.add_argument("-mh", "--max-hops", type=_positive_int, help=f"最大跳数（默认 {DEFAULT_MAX_HOPS}）")
    parser.add_argument("-f", "--filter", dest="filter_workers", type=_positive_int, help="优选筛选并发")
    parser.add_argument("-d", "--download", dest="download_workers", type=_positive_int, help="优选测速并发")
    parser.add_argument("-u", "--url", help="下载测速地址（配合 --download-speed）")
    parser.add_argument("--download-speed", action="store_true", help="启用下载测速")
    parser.add_argument("-s", "--slim", dest="slim_workers", type=_positive_int, help="子网精简并发（显式传入即启用）")
    parser.add_argument("--proxyip-check", action="store_true", help="启用 ProxyIP 检测")
    parser.add_argument("--risk-check", action="store_true", help="启用风险检测")
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
