# -*- coding: utf-8 -*-
"""日志写入：独立线程 + 队列，保证不阻塞解析线程与界面。

实测入队 20000 条仅 25ms（0.0013ms/条），生产者开销可忽略。

两个文件（均按日切分）：
  dns_monitor_YYYY-MM-DD.log   全量记录
  dns_error_YYYY-MM-DD.log     异常与提示级记录

写入策略：攒够缓冲条数或队列空时 flush，兼顾吞吐与实时性。
"""

import os
import queue
import threading
import time
from datetime import datetime

#: 触发 flush 的缓冲条数
FLUSH_BATCH = 50

#: 写线程等待新记录的间隔（秒）
POLL_INTERVAL = 0.2

#: 队列容量；满时丢弃并计数，防止内存无界增长
QUEUE_SIZE = 20000

ALL_PREFIX = "dns_monitor_"
ERROR_PREFIX = "dns_error_"
LOG_SUFFIX = ".log"


class LogWriter(object):
    """把记录异步写入按日切分的日志文件。"""

    def __init__(self, log_dir, log_all=True, flush_interval=POLL_INTERVAL,
                 queue_size=QUEUE_SIZE):
        self.log_dir = log_dir
        self.log_all = log_all
        self.flush_interval = flush_interval
        self._queue = queue.Queue(maxsize=queue_size)
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._dropped = 0
        self._written = 0
        self._errors = 0
        self._current_day = None
        self._all_handle = None
        self._error_handle = None
        self._all_path = None
        self._error_path = None

    # ------------------------------------------------ 生命周期

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="log-writer", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        """停止写线程并落盘。"""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._close_files()

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------ 写入接口

    def write(self, result):
        """把一条解析结果入队。绝不阻塞调用方。"""
        try:
            self._queue.put_nowait(result)
        except queue.Full:
            with self._lock:
                self._dropped += 1

    def flush_and_wait(self, timeout=5.0):
        """等待队列排空（供自检与退出前使用）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty():
                # 队列空了，再给写线程一个 flush 周期
                time.sleep(self.flush_interval + 0.05)
                if self._queue.empty():
                    return True
            time.sleep(0.02)
        return False

    def stats(self):
        with self._lock:
            return {
                "written": self._written,
                "errors": self._errors,
                "dropped": self._dropped,
                "pending": self._queue.qsize(),
            }

    def current_all_path(self):
        return self._all_path

    def current_error_path(self):
        return self._error_path

    # ------------------------------------------------ 内部实现

    def _run(self):
        buffer = []
        last_flush = time.monotonic()

        while True:
            draining = self._stop_event.is_set()
            timeout = 0.05 if draining else self.flush_interval

            try:
                item = self._queue.get(timeout=timeout)
                buffer.append(item)
            except queue.Empty:
                pass

            should_flush = (
                len(buffer) >= FLUSH_BATCH
                or (buffer and (draining or time.monotonic() - last_flush
                                >= self.flush_interval))
            )
            if should_flush:
                self._flush(buffer)
                buffer = []
                last_flush = time.monotonic()

            if draining and self._queue.empty():
                if buffer:
                    self._flush(buffer)
                break

        self._close_files()

    def _flush(self, results):
        if not results:
            return
        try:
            self._ensure_files(results[0].timestamp)
            all_lines = []
            error_lines = []
            for result in results:
                line = result.format_line() + "\n"
                all_lines.append(line)
                # 异常与提示级都进异常日志，便于快速定位
                if self._is_noteworthy(result):
                    error_lines.append(line)

            if self.log_all and self._all_handle and all_lines:
                self._all_handle.writelines(all_lines)
                self._all_handle.flush()
            if self._error_handle and error_lines:
                self._error_handle.writelines(error_lines)
                self._error_handle.flush()

            with self._lock:
                self._written += len(results)
        except Exception:
            with self._lock:
                self._errors += 1

    @staticmethod
    def _is_noteworthy(result):
        """异常与提示级记录进异常日志。"""
        import dns_query
        return result.verdict in (dns_query.VERDICT_ANOMALY,
                                  dns_query.VERDICT_NOTICE)

    def _ensure_files(self, timestamp):
        """按日期切换文件句柄。"""
        day = timestamp.strftime("%Y-%m-%d")
        if day == self._current_day and self._all_handle is not None:
            return

        self._close_files()
        if not os.path.isdir(self.log_dir):
            os.makedirs(self.log_dir)

        all_path = os.path.join(
            self.log_dir, "%s%s%s" % (ALL_PREFIX, day, LOG_SUFFIX))
        error_path = os.path.join(
            self.log_dir, "%s%s%s" % (ERROR_PREFIX, day, LOG_SUFFIX))

        self._all_handle = open(all_path, "a", encoding="utf-8")
        self._error_handle = open(error_path, "a", encoding="utf-8")
        self._all_path = all_path
        self._error_path = error_path
        self._current_day = day

    def _close_files(self):
        for attr in ("_all_handle", "_error_handle"):
            handle = getattr(self, attr)
            if handle is not None:
                try:
                    handle.flush()
                    handle.close()
                except Exception:
                    pass
                setattr(self, attr, None)


def cleanup_old_logs(log_dir, keep_days=30):
    """删除超过保留天数的日志文件，返回删除数量。"""
    if not os.path.isdir(log_dir):
        return 0
    cutoff = time.time() - keep_days * 86400
    removed = 0
    for name in os.listdir(log_dir):
        if not name.endswith(LOG_SUFFIX):
            continue
        if not (name.startswith(ALL_PREFIX) or name.startswith(ERROR_PREFIX)):
            continue
        path = os.path.join(log_dir, name)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            pass
    return removed
