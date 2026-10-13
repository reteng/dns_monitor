# -*- coding: utf-8 -*-
"""监测调度引擎：周期触发解析、线程池并发、规则判定、结果投递。

架构要点：
- 单调度线程按固定节拍触发，避免逐轮累积漂移
- 域名 × DNS 服务器 的笛卡尔积在线程池中并发执行
- 工作线程只往队列投递结果，绝不触碰任何 tkinter 控件
- 配置在每轮边界读取，热更新不打断进行中的查询

并发数实测依据：10 个任务下 workers=4 耗时 2084ms（重试排队阻塞），
workers=8 仅 42ms。并发数过低会让超时重试串行化，直接拖长单轮周期。
"""

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

import dns_query
import config as config_mod

#: 单轮总时长护栏系数：估算耗时 × 该系数后仍超时则强制进入下一轮
ROUND_GUARD_FACTOR = 3.0

#: 护栏下限（秒），避免小配置下过于激进的截断
ROUND_GUARD_MIN = 10.0


class DomainState(object):
    """单个域名的跨轮次状态（用于「结果与上次不同」判定）。"""

    __slots__ = ("last_ips", "has_history")

    def __init__(self):
        self.last_ips = None
        self.has_history = False


def effective_workers(conf):
    """计算实际并发数：不低于任务数，避免重试任务排队串行化。"""
    servers = conf.get("dns_servers", [])
    active_domains = [d for d in conf.get("domains", [])
                      if d.get("enabled", True)]
    tasks = max(1, len(servers) * max(1, len(active_domains)))
    configured = int(conf.get("max_workers", 8) or 8)
    return max(configured, min(tasks, 64))


def apply_rules(result, domain_conf, state):
    """对单条解析结果做规则判定，就地填写 verdict 与 note。

    判定顺序（后者不覆盖前者）：
      1. 基础规则：非 ok 状态即为异常
      2. 期望 IP 校验：结果不在期望列表内为异常
      3. 变化提示：与上次结果不同为提示级（不计入异常统计）
    """
    if result.status != dns_query.STATUS_OK:
        result.verdict = dns_query.VERDICT_ANOMALY
        return

    expected = domain_conf.get("expected_ips") or []
    if expected:
        unexpected = [ip for ip in result.ips if ip not in expected]
        if unexpected:
            result.verdict = dns_query.VERDICT_ANOMALY
            result.note = "解析为 %s，不在期望列表内 (%s)" % (
                ", ".join(result.ips), ", ".join(expected))
            state.last_ips = _ip_key(result.ips)
            state.has_history = True
            return

    # 变化提示：仅在开启且已有历史时比较
    # 用排序后的元组做键 —— 多 IP 轮询返回顺序不同（实测 www.baidu.com
    # 会在两次查询间调换顺序）不算结果变化，否则会产生大量误报
    current = _ip_key(result.ips)
    if domain_conf.get("alert_on_change", True) and state.has_history:
        if state.last_ips is not None and current != state.last_ips:
            result.verdict = dns_query.VERDICT_NOTICE
            result.note = "结果与上次不同，上次为 %s" % ", ".join(
                state.last_ips)

    state.last_ips = current
    state.has_history = True


def _ip_key(ips):
    """生成与顺序无关的地址比较键。"""
    return tuple(sorted(str(ip) for ip in ips))


class MonitorEngine(object):
    """监测引擎：启动后按间隔循环执行查询，结果投递到输出队列。"""

    def __init__(self, conf, output_queue, on_round_start=None):
        self._conf = conf
        self._output = output_queue
        self._on_round_start = on_round_start
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._reload_flag = threading.Event()
        self._pending_conf = None
        self._rounds = 0
        self._queries = 0
        self._anomalies = 0
        self._notices = 0
        self._dropped = 0
        self._states = {}
        self._last_round_ms = 0.0

    # ------------------------------------------------ 生命周期

    def start(self):
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="monitor-engine", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        """置位停止标志并等待调度线程退出。进行中的查询不会阻塞退出。"""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def update_config(self, conf):
        """热更新配置：在下一轮边界生效。"""
        with self._lock:
            self._pending_conf = conf
        self._reload_flag.set()

    def _take_config(self):
        """取出当前生效的配置（含热更新）。"""
        with self._lock:
            if self._pending_conf is not None:
                self._conf = self._pending_conf
                self._pending_conf = None
            return self._conf

    # ------------------------------------------------ 统计

    def stats(self):
        with self._lock:
            return {
                "rounds": self._rounds,
                "queries": self._queries,
                "anomalies": self._anomalies,
                "notices": self._notices,
                "dropped": self._dropped,
                "last_round_ms": self._last_round_ms,
            }

    def reset_stats(self):
        with self._lock:
            self._rounds = 0
            self._queries = 0
            self._anomalies = 0
            self._notices = 0
            self._dropped = 0
            self._last_round_ms = 0.0

    # ------------------------------------------------ 主循环

    def _run(self):
        while not self._stop_event.is_set():
            conf = self._take_config()
            self._reload_flag.clear()

            interval = float(conf.get("interval_seconds", 30) or 30)
            round_start = time.monotonic()

            try:
                self._run_round(conf)
            except Exception:
                # 单轮异常不能终止整个监测
                pass

            if self._stop_event.is_set():
                break

            # 固定节拍：扣除本轮耗时，避免逐轮累积漂移
            elapsed = time.monotonic() - round_start
            remaining = interval - elapsed
            if remaining > 0:
                # 用 Event.wait 替代 sleep，停止时能立即响应
                self._stop_event.wait(remaining)

    def _run_round(self, conf):
        """执行一轮：对所有启用域名 × DNS 服务器并发查询。"""
        servers = conf.get("dns_servers", [])
        domains = [d for d in conf.get("domains", []) if d.get("enabled", True)]
        if not servers or not domains:
            return

        qtype = dns_query.parse_qtype(conf.get("query_type", "A"))
        timeout = float(conf.get("timeout_seconds", 2.0) or 2.0)
        retries = int(conf.get("retries", 2) or 0)
        workers = effective_workers(conf)

        with self._lock:
            self._rounds += 1
            round_number = self._rounds

        if self._on_round_start is not None:
            try:
                self._on_round_start(round_number)
            except Exception:
                pass

        start = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=workers,
                                      thread_name_prefix="dns-query")
        try:
            futures = []
            for domain in domains:
                for server in servers:
                    futures.append(executor.submit(
                        self._query_one, conf, domain, server, qtype,
                        timeout, retries))
            wait(futures, timeout=self._round_guard(conf, workers))
        finally:
            executor.shutdown(wait=False)

        with self._lock:
            self._last_round_ms = (time.monotonic() - start) * 1000.0

    @staticmethod
    def _round_guard(conf, workers):
        """单轮总时长护栏：防止极端故障下单轮无限拉长。"""
        servers = len(conf.get("dns_servers", [])) or 1
        domains = max(1, len([d for d in conf.get("domains", [])
                              if d.get("enabled", True)]))
        timeout = float(conf.get("timeout_seconds", 2.0) or 2.0)
        retries = int(conf.get("retries", 2) or 0) + 1
        estimate = servers * domains * timeout * retries / max(1, workers)
        return max(ROUND_GUARD_MIN, estimate * ROUND_GUARD_FACTOR)

    def _query_one(self, conf, domain, server, qtype, timeout, retries):
        """查询单个 域名×服务器 组合并投递结果。"""
        name = domain.get("name", "")
        try:
            address, port = config_mod.parse_server(server)
        except (ValueError, TypeError):
            address, port = server, 53

        try:
            result = dns_query.query_server(
                address, name, timeout=timeout, retries=retries,
                qtype=qtype, port=port)
        except Exception as exc:  # noqa: BLE001 - 兜底，任何异常都要有记录
            result = dns_query.DnsResult(
                timestamp=__import__("datetime").datetime.now(),
                server=server, name=name, qtype=qtype,
                status=dns_query.STATUS_NETWORK,
                error="%s: %s" % (type(exc).__name__, exc))

        result.server = server

        state = self._states.get((name, server))
        if state is None:
            state = DomainState()
            self._states[(name, server)] = state
        apply_rules(result, domain, state)

        with self._lock:
            self._queries += 1
            if result.verdict == dns_query.VERDICT_ANOMALY:
                self._anomalies += 1
            elif result.verdict == dns_query.VERDICT_NOTICE:
                self._notices += 1

        self._emit(result)

    def _emit(self, result):
        """把结果投入输出队列；满时丢弃并计数（绝不阻塞工作线程）。"""
        try:
            self._output.put_nowait(result)
        except queue.Full:
            with self._lock:
                self._dropped += 1
