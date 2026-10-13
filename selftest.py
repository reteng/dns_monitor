# -*- coding: utf-8 -*-
"""无 GUI 自检：验证 DNS 报文层、配置层、日志层、调度层与规则判定。

用法：
    python selftest.py            # 全部（含联网用例）
    python selftest.py --offline  # 仅离线用例（不依赖网络）

联网用例在断网环境下会跳过而非失败，保证自检始终可用。
"""

import ast
import io
import os
import re
import shutil
import struct
import sys
import tempfile
import time

import dns_query
from dns_query import (
    DnsFormatError, DnsIdMismatch, QTYPE_A, QTYPE_AAAA,
    STATUS_EMPTY, STATUS_MALFORMED, STATUS_NXDOMAIN, STATUS_OK,
    STATUS_TIMEOUT, build_query, encode_name, parse_response, query_server,
)

# ---------------------------------------------------------------- 测试框架

_PASSED = []
_FAILED = []
_SKIPPED = []


def check(label, condition, detail=""):
    """记录一条断言结果。"""
    if condition:
        _PASSED.append(label)
        print("  [通过] %s" % label)
    else:
        _FAILED.append((label, detail))
        print("  [失败] %s  %s" % (label, detail))


def skip(label, reason):
    _SKIPPED.append((label, reason))
    print("  [跳过] %s (%s)" % (label, reason))


def section(title):
    print("\n=== %s ===" % title)


# ---------------------------------------------------------------- 报文层

def test_encode_name():
    section("域名编码")
    check("普通域名编码", encode_name("example.com") ==
          b"\x07example\x03com\x00")
    check("末尾点号被剥离", encode_name("example.com.") ==
          b"\x07example\x03com\x00")
    check("多级域名", encode_name("a.b.c.example.com") ==
          b"\x01a\x01b\x01c\x07example\x03com\x00")
    try:
        encode_name("")
        check("空域名应报错", False, "未抛出异常")
    except ValueError:
        check("空域名应报错", True)
    try:
        encode_name("a..b")
        check("空标签应报错", False, "未抛出异常")
    except ValueError:
        check("空标签应报错", True)
    try:
        encode_name("x" * 64 + ".com")
        check("超长标签应报错", False, "未抛出异常")
    except ValueError:
        check("超长标签应报错", True)


def test_build_query():
    section("查询报文构造")
    tid, packet = build_query("example.com", QTYPE_A)
    check("事务 ID 在合法范围", 0 <= tid <= 0xFFFF)
    check("报文头 12 字节 + 问题区", len(packet) == 12 + 13 + 4)
    header = packet[:12]
    check("递归期望位置位 (0x0100)", header[2:4] == b"\x01\x00")
    check("QDCOUNT=1", header[4:6] == b"\x00\x01")
    check("ANCOUNT=0", header[6:8] == b"\x00\x00")


def test_parse_roundtrip():
    section("报文解析：自造响应往返")
    tid, query = build_query("example.com", QTYPE_A)
    # 手工拼一个响应：复制问题区，追加一条 A 记录
    question = query[12:]
    answer = b"\xc0\x0c" + struct_pack_rr(QTYPE_A, 4, b"\x01\x01\x01\x01")
    flags = 0x8180  # QR=1, RD=1, RA=1, rcode=0
    resp = struct_pack_header(tid, flags, 1, 1) + question + answer
    parsed = parse_response(resp, tid)
    check("解析出 1 条 A 记录", parsed.ips == ["1.1.1.1"])
    check("rcode=0", parsed.rcode == 0)
    check("TC 未置位", parsed.tc == 0)


def struct_pack_header(tid, flags, qd, an):
    import struct
    return struct.pack(">HHHHHH", tid, flags, qd, an, 0, 0)


def struct_pack_rr(rtype, rdlength, rdata, ttl=300):
    import struct
    return struct.pack(">HHIH", rtype, 1, ttl, rdlength) + rdata


def test_parse_cname_compression():
    section("报文解析：CNAME 与压缩指针")
    import struct
    tid = 0x1234
    question = encode_name("www.example.com") + struct.pack(">HH", 1, 1)
    # 答案1: CNAME -> target.example.com（名字用压缩指针指向问题区）
    target = encode_name("target.example.com")
    a1 = b"\xc0\x0c" + struct_pack_rr(5, len(target), target)
    # 答案2: A 记录，名字指向答案1的 rdata 起始处
    # 问题区末尾偏移 = 12 + len(question)；答案1 名字2字节+RR头10字节=12
    cname_rdata_off = 12 + len(question) + 12
    a2 = struct.pack(">H", 0xC000 | cname_rdata_off) + \
        struct_pack_rr(1, 4, b"\x02\x02\x02\x02")
    resp = struct_pack_header(tid, 0x8180, 1, 2) + question + a1 + a2
    parsed = parse_response(resp, tid)
    check("CNAME 链被解析", parsed.cnames == ["target.example.com"],
          "实际: %s" % parsed.cnames)
    check("A 记录被解析", parsed.ips == ["2.2.2.2"], "实际: %s" % parsed.ips)


def test_parse_errors():
    section("报文解析：畸形与非法输入")
    tid, query = build_query("example.com", QTYPE_A)

    try:
        parse_response(b"\x00" * 5, tid)
        check("过短报文应报错", False, "未抛出异常")
    except DnsFormatError:
        check("过短报文应报错", True)

    try:
        parse_response(query, tid)  # 查询报文 QR=0，不是响应
        check("QR=0 应被拒", False, "未抛出异常")
    except DnsFormatError:
        check("QR=0 应被拒", True)

    other = struct_pack_header(0x9999, 0x8180, 1, 0) + query[12:]
    try:
        parse_response(other, tid)
        check("事务 ID 不匹配应抛 DnsIdMismatch", False, "未抛出异常")
    except DnsIdMismatch:
        check("事务 ID 不匹配应抛 DnsIdMismatch", True)

    # 答案数虚报但数据缺失
    bad = struct_pack_header(tid, 0x8180, 1, 5) + query[12:]
    try:
        parse_response(bad, tid)
        check("答案区截断应报错", False, "未抛出异常")
    except DnsFormatError:
        check("答案区截断应报错", True)

    # 压缩指针环路：CNAME 的 rdata 指向它自己
    question = query[12:]
    rdata_off = 12 + len(question) + 12  # 名字2字节 + RR头10字节
    loop_rr = b"\xc0\x0c" + struct_pack_rr(
        5, 2, struct.pack(">H", 0xC000 | rdata_off))
    resp = struct_pack_header(tid, 0x8180, 1, 1) + question + loop_rr
    try:
        parse_response(resp, tid)
        check("指针环路应被拦截", False, "未抛出异常")
    except DnsFormatError:
        check("指针环路应被拦截", True)


def test_rcode_status_mapping():
    section("状态判定：rcode 与 NODATA")
    tid, query = build_query("example.com", QTYPE_A)
    question = query[12:]

    for rcode, expected_status, label in (
            (3, STATUS_NXDOMAIN, "NXDOMAIN -> 域名不存在"),
            (2, dns_query.STATUS_RCODE_ERROR, "SERVFAIL -> 返回错误"),
            (5, dns_query.STATUS_RCODE_ERROR, "REFUSED -> 返回错误")):
        resp = struct_pack_header(tid, 0x8180 | rcode, 1, 0) + question
        parsed = parse_response(resp, tid)
        result = _make_result_from(parsed, "example.com", "1.1.1.1", QTYPE_A)
        check(label, result.status == expected_status,
              "实际: %s" % result.status)

    # NODATA：NOERROR 但无答案
    resp = struct_pack_header(tid, 0x8180, 1, 0) + question
    parsed = parse_response(resp, tid)
    result = _make_result_from(parsed, "www.qq.com", "1.1.1.1", QTYPE_AAAA)
    check("NODATA -> 空结果 (核心：只判 rcode 会漏报)",
          result.status == STATUS_EMPTY, "实际: %s" % result.status)


def _make_result_from(parsed, name, server, qtype):
    """复现 query_server 内部的状态映射逻辑，供离线用例使用。"""
    import datetime
    rcode = parsed.rcode
    if rcode == 3:
        status = STATUS_NXDOMAIN
    elif rcode != 0:
        status = dns_query.STATUS_RCODE_ERROR
    elif not parsed.ips:
        status = STATUS_EMPTY
    else:
        status = STATUS_OK
    return dns_query.DnsResult(
        timestamp=datetime.datetime.now(), server=server, name=name,
        qtype=qtype, status=status, rcode=rcode,
        rcode_name=dns_query.RCODE_NAMES.get(rcode), ips=parsed.ips)


def test_format_line():
    section("记录文本规范化")
    import datetime
    ts = datetime.datetime(2026, 10, 13, 12, 0, 33)

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["1.1.1.1"])
    line = r.format_line()
    check("正常行格式与参考一致",
          line == "2026-10-13 12:00:33 example.com 通过 223.5.5.5 解析为 1.1.1.1",
          "实际: %s" % line)

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["1.1.1.1", "2.2.2.2"])
    check("多 IP 用逗号分隔",
          r.format_line().endswith("解析为 1.1.1.1, 2.2.2.2"),
          "实际: %s" % r.format_line())

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="gone.example.com", qtype=QTYPE_A,
                            status=STATUS_NXDOMAIN, rcode=3,
                            rcode_name="NXDOMAIN")
    line = r.format_line()
    check("NXDOMAIN 行含 rcode 名称", "NXDOMAIN" in line and "解析失败" in line,
          "实际: %s" % line)

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_TIMEOUT, timeout_ms=2000,
                            attempts=3, elapsed_ms=6000.0)
    line = r.format_line()
    check("超时行含总等待、单次超时与重试次数",
          "解析超时" in line and "共等待 6000ms" in line
          and "单次超时 2000ms" in line and "重试 2 次" in line,
          "实际: %s" % line)

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="www.qq.com", qtype=QTYPE_AAAA,
                            status=STATUS_EMPTY, rcode=0, rcode_name="NOERROR")
    line = r.format_line()
    check("空结果行含记录类型", "空结果" in line and "AAAA" in line,
          "实际: %s" % line)

    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["1.2.3.4"],
                            note="结果与上次不同")
    check("提示信息以括号追加", r.format_line().endswith("(结果与上次不同)"),
          "实际: %s" % r.format_line())


def test_format_consistency():
    section("格式一致性：所有状态行都含必需字段")
    import datetime
    ts = datetime.datetime(2026, 10, 13, 12, 0, 33)
    for status in sorted(dns_query.ABNORMAL_STATUSES | {STATUS_OK}):
        r = dns_query.DnsResult(timestamp=ts, server="8.8.8.8",
                                name="test.example.com", qtype=QTYPE_A,
                                status=status, error="模拟错误",
                                timeout_ms=2000, attempts=2)
        line = r.format_line()
        has_ts = line.startswith("2026-10-13 12:00:33")
        has_name = "test.example.com" in line
        has_server = "8.8.8.8" in line
        check("状态 %-10s 行含 时间/域名/服务器" % status,
              has_ts and has_name and has_server, "实际: %s" % line)


# ---------------------------------------------------------------- 配置层

def test_config():
    section("配置层")
    import config as cfg_mod

    defaults = cfg_mod.default_config()
    check("默认配置含必需键",
          all(k in defaults for k in (
              "interval_seconds", "timeout_seconds", "retries",
              "max_workers", "dns_servers", "domains", "log_dir")),
          "实际键: %s" % sorted(defaults))

    tmpdir = tempfile.mkdtemp(prefix="dnsmon_cfg_")
    try:
        path = os.path.join(tmpdir, "config.json")
        conf = cfg_mod.default_config()
        conf["interval_seconds"] = 42
        conf["domains"] = [{"name": "example.com", "enabled": True,
                            "expected_ips": ["1.1.1.1"],
                            "alert_on_change": True}]
        cfg_mod.save_config(conf, path)
        check("配置文件已写出", os.path.isfile(path))

        loaded = cfg_mod.load_config(path)
        check("间隔往返一致", loaded["interval_seconds"] == 42,
              "实际: %s" % loaded["interval_seconds"])
        check("域名往返一致",
              loaded["domains"][0]["name"] == "example.com")

        # 损坏文件应回退默认值而非崩溃
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ 这不是合法 JSON")
        fallback = cfg_mod.load_config(path)
        check("损坏配置回退到默认值",
              fallback["interval_seconds"] == defaults["interval_seconds"])

        # 非法值应被规整
        conf2 = cfg_mod.default_config()
        conf2["interval_seconds"] = -5
        conf2["retries"] = "abc"
        conf2["dns_servers"] = ["not-an-ip", "8.8.8.8"]
        conf2["domains"] = [{"name": ""}, {"name": "ok.com"}]
        fixed = cfg_mod.normalize_config(conf2)
        check("负数间隔被纠正", fixed["interval_seconds"] > 0,
              "实际: %s" % fixed["interval_seconds"])
        check("非法重试数被纠正", isinstance(fixed["retries"], int),
              "实际: %s" % repr(fixed["retries"]))
        check("非法 DNS 服务器被剔除",
              fixed["dns_servers"] == ["8.8.8.8"],
              "实际: %s" % fixed["dns_servers"])
        check("空域名被剔除", len(fixed["domains"]) == 1,
              "实际: %s" % fixed["domains"])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_config_validation():
    section("配置校验：域名与 IP")
    import config as cfg_mod
    check("合法域名通过", cfg_mod.is_valid_domain("example.com"))
    check("多级域名通过", cfg_mod.is_valid_domain("a.b.example.com"))
    check("带连字符域名通过", cfg_mod.is_valid_domain("my-host.example.com"))
    check("空域名被拒", not cfg_mod.is_valid_domain(""))
    check("含空格域名被拒", not cfg_mod.is_valid_domain("bad domain.com"))
    check("无点号被拒", not cfg_mod.is_valid_domain("localhost"))
    check("中文域名通过(IDNA)",
          cfg_mod.is_valid_domain("测试.example.com"))

    check("合法 IPv4 通过", cfg_mod.is_valid_ip("1.1.1.1"))
    check("超范围 IPv4 被拒", not cfg_mod.is_valid_ip("999.1.1.1"))
    check("合法 IPv6 通过", cfg_mod.is_valid_ip("2001:db8::1"))
    check("空 IP 被拒", not cfg_mod.is_valid_ip(""))
    check("乱码被拒", not cfg_mod.is_valid_ip("abc"))


def test_app_dir():
    section("路径解析：app_dir 不依赖 cwd")
    import config as cfg_mod
    before = cfg_mod.app_dir()
    old_cwd = os.getcwd()
    try:
        os.chdir(tempfile.gettempdir())
        after = cfg_mod.app_dir()
        check("切换 cwd 后 app_dir 不变", before == after,
              "%s -> %s" % (before, after))
        resolved = cfg_mod.resolve_log_dir("logs")
        check("相对日志目录基于 app_dir 解析",
              resolved.startswith(before) and resolved.endswith("logs"),
              "实际: %s" % resolved)
    finally:
        os.chdir(old_cwd)

    abs_target = tempfile.gettempdir()
    check("绝对路径原样保留",
          cfg_mod.resolve_log_dir(abs_target) == abs_target)


# ---------------------------------------------------------------- 日志层

def test_log_writer():
    section("日志层")
    import log_writer

    tmpdir = tempfile.mkdtemp(prefix="dnsmon_log_")
    try:
        writer = log_writer.LogWriter(tmpdir, flush_interval=0.05)
        writer.start()

        import datetime
        ts = datetime.datetime(2026, 10, 13, 12, 0, 33)
        normal = dns_query.DnsResult(
            timestamp=ts, server="223.5.5.5", name="example.com",
            qtype=QTYPE_A, status=STATUS_OK, ips=["1.1.1.1"])
        anomaly = dns_query.DnsResult(
            timestamp=ts, server="223.5.5.5", name="gone.example.com",
            qtype=QTYPE_A, status=STATUS_NXDOMAIN, rcode=3,
            rcode_name="NXDOMAIN")
        notice = dns_query.DnsResult(
            timestamp=ts, server="223.5.5.5", name="example.com",
            qtype=QTYPE_A, status=STATUS_OK, ips=["9.9.9.9"],
            note="结果与上次不同")
        notice.verdict = dns_query.VERDICT_NOTICE

        writer.write(normal)
        writer.write(anomaly)
        writer.write(notice)
        writer.flush_and_wait(timeout=3.0)

        all_path = writer.current_all_path()
        err_path = writer.current_error_path()
        check("全量日志已创建", os.path.isfile(all_path))
        check("异常日志已创建", os.path.isfile(err_path))

        with io.open(all_path, encoding="utf-8") as handle:
            all_lines = [l.rstrip("\n") for l in handle if l.strip()]
        with io.open(err_path, encoding="utf-8") as handle:
            err_lines = [l.rstrip("\n") for l in handle if l.strip()]

        check("全量日志含 3 条", len(all_lines) == 3,
              "实际 %d 条: %s" % (len(all_lines), all_lines))
        check("异常日志含 2 条（异常+提示）", len(err_lines) == 2,
              "实际 %d 条: %s" % (len(err_lines), err_lines))
        check("正常行格式正确",
              all_lines[0] ==
              "2026-10-13 12:00:33 example.com 通过 223.5.5.5 解析为 1.1.1.1",
              "实际: %s" % all_lines[0])
        check("异常日志含 NXDOMAIN 行",
              any("NXDOMAIN" in l for l in err_lines), str(err_lines))

        writer.stop()
        check("写线程已停止", not writer.is_alive())

        stats = writer.stats()
        check("统计记录了写入条数", stats["written"] == 3,
              "实际: %s" % stats)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_log_writer_backpressure():
    section("日志层：高频写入不阻塞")
    import log_writer
    tmpdir = tempfile.mkdtemp(prefix="dnsmon_log_bp_")
    try:
        writer = log_writer.LogWriter(tmpdir, flush_interval=0.05)
        writer.start()
        import datetime
        ts = datetime.datetime(2026, 10, 13, 12, 0, 33)
        count = 5000
        start = time.perf_counter()
        for i in range(count):
            writer.write(dns_query.DnsResult(
                timestamp=ts, server="223.5.5.5", name="d%d.example.com" % i,
                qtype=QTYPE_A, status=STATUS_OK, ips=["1.1.1.%d" % (i % 255)]))
        enqueue_ms = (time.perf_counter() - start) * 1000.0
        check("入队 %d 条耗时 < 1000ms（实测约 %.0fms）" % (count, enqueue_ms),
              enqueue_ms < 1000.0, "实际: %.1fms" % enqueue_ms)
        writer.flush_and_wait(timeout=10.0)
        check("全部落盘", writer.stats()["written"] == count,
              "实际: %s" % writer.stats())
        writer.stop()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------- 规则层

def test_rules():
    section("异常判定规则")
    import monitor_engine as engine

    domain = {"name": "example.com", "enabled": True,
              "expected_ips": ["1.1.1.1"], "alert_on_change": True}
    state = engine.DomainState()

    import datetime
    ts = datetime.datetime(2026, 10, 13, 12, 0, 33)

    # 正常且匹配期望
    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["1.1.1.1"])
    engine.apply_rules(r, domain, state)
    check("匹配期望 IP 判为正常",
          r.verdict == dns_query.VERDICT_OK, "实际: %s" % r.verdict)

    # 不匹配期望
    r = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["6.6.6.6"])
    engine.apply_rules(r, domain, state)
    check("IP 不在期望列表判为异常",
          r.verdict == dns_query.VERDICT_ANOMALY and
          "期望" in (r.note or ""),
          "实际: %s / %s" % (r.verdict, r.note))

    # 结果与上次不同（期望列表为空，只看变化）
    d2 = {"name": "cdn.example.com", "enabled": True,
          "expected_ips": [], "alert_on_change": True}
    st2 = engine.DomainState()
    first = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                                name="cdn.example.com", qtype=QTYPE_A,
                                status=STATUS_OK, ips=["1.1.1.1"])
    engine.apply_rules(first, d2, st2)
    check("首次解析不判为变化", first.verdict == dns_query.VERDICT_OK,
          "实际: %s" % first.verdict)

    second = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                                 name="cdn.example.com", qtype=QTYPE_A,
                                 status=STATUS_OK, ips=["2.2.2.2"])
    engine.apply_rules(second, d2, st2)
    check("结果变化判为提示级",
          second.verdict == dns_query.VERDICT_NOTICE,
          "实际: %s / %s" % (second.verdict, second.note))

    third = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                                name="cdn.example.com", qtype=QTYPE_A,
                                status=STATUS_OK, ips=["2.2.2.2"])
    engine.apply_rules(third, d2, st2)
    check("结果未变不重复提示", third.verdict == dns_query.VERDICT_OK,
          "实际: %s" % third.verdict)

    # 多 IP 轮询换序不算变化（实测 www.baidu.com 会调换返回顺序）
    reordered = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                                    name="cdn.example.com", qtype=QTYPE_A,
                                    status=STATUS_OK,
                                    ips=["2.2.2.2", "3.3.3.3"])
    engine.apply_rules(reordered, d2, st2)
    check("新增 IP 判为变化", reordered.verdict == dns_query.VERDICT_NOTICE,
          "实际: %s" % reordered.verdict)

    same_set = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                                   name="cdn.example.com", qtype=QTYPE_A,
                                   status=STATUS_OK,
                                   ips=["3.3.3.3", "2.2.2.2"])
    engine.apply_rules(same_set, d2, st2)
    check("仅顺序不同不算变化（避免轮询误报）",
          same_set.verdict == dns_query.VERDICT_OK,
          "实际: %s / %s" % (same_set.verdict, same_set.note))

    # 关闭变化提示
    d3 = {"name": "cdn.example.com", "enabled": True,
          "expected_ips": [], "alert_on_change": False}
    st3 = engine.DomainState()
    a = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="cdn.example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["1.1.1.1"])
    engine.apply_rules(a, d3, st3)
    b = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                            name="cdn.example.com", qtype=QTYPE_A,
                            status=STATUS_OK, ips=["2.2.2.2"])
    engine.apply_rules(b, d3, st3)
    check("关闭后变化不提示", b.verdict == dns_query.VERDICT_OK,
          "实际: %s" % b.verdict)

    # 异常状态优先于变化判定
    d4 = {"name": "cdn.example.com", "enabled": True,
          "expected_ips": [], "alert_on_change": True}
    st4 = engine.DomainState()
    ok = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                             name="cdn.example.com", qtype=QTYPE_A,
                             status=STATUS_OK, ips=["1.1.1.1"])
    engine.apply_rules(ok, d4, st4)
    bad = dns_query.DnsResult(timestamp=ts, server="223.5.5.5",
                              name="cdn.example.com", qtype=QTYPE_A,
                              status=STATUS_TIMEOUT, timeout_ms=2000,
                              attempts=3)
    engine.apply_rules(bad, d4, st4)
    check("异常状态判为异常（不被变化覆盖）",
          bad.verdict == dns_query.VERDICT_ANOMALY,
          "实际: %s" % bad.verdict)


def test_ui_status_consistency():
    section("界面文案：状态与判定不得自相矛盾")
    import gui

    import datetime
    ts = datetime.datetime(2026, 10, 13, 12, 0, 33)

    # 期望 IP 不匹配：解析成功但判定为异常，文案必须是「IP不符」而非「正常」
    mismatched = dns_query.DnsResult(
        timestamp=ts, server="223.5.5.5", name="example.com", qtype=QTYPE_A,
        status=STATUS_OK, ips=["1.2.3.4"], verdict=dns_query.VERDICT_ANOMALY,
        note="解析为 1.2.3.4，不在期望列表内 (9.9.9.9)")
    text = gui.MonitorTab._status_text(mismatched)
    check("期望IP不匹配显示为「IP不符」", text == "IP不符",
          "实际: %s" % text)

    # 解析失败时仍显示具体失败原因
    failed = dns_query.DnsResult(
        timestamp=ts, server="223.5.5.5", name="gone.example.com",
        qtype=QTYPE_A, status=STATUS_NXDOMAIN, rcode=3, rcode_name="NXDOMAIN")
    check("NXDOMAIN 显示为「域名不存在」",
          gui.MonitorTab._status_text(failed) == "域名不存在",
          "实际: %s" % gui.MonitorTab._status_text(failed))

    # 变化提示优先显示
    changed = dns_query.DnsResult(
        timestamp=ts, server="223.5.5.5", name="cdn.example.com",
        qtype=QTYPE_A, status=STATUS_OK, ips=["2.2.2.2"],
        verdict=dns_query.VERDICT_NOTICE, note="结果与上次不同")
    check("变化提示显示为「结果变化」",
          gui.MonitorTab._status_text(changed) == "结果变化",
          "实际: %s" % gui.MonitorTab._status_text(changed))

    # 正常情况下不得显示异常文案
    normal = dns_query.DnsResult(
        timestamp=ts, server="223.5.5.5", name="example.com", qtype=QTYPE_A,
        status=STATUS_OK, ips=["1.1.1.1"])
    check("正常结果显示为「正常」",
          gui.MonitorTab._status_text(normal) == "正常",
          "实际: %s" % gui.MonitorTab._status_text(normal))

    # 状态为异常但 verdict 未显式设置时，默认应为异常（防止漏记日志）
    implicit = dns_query.DnsResult(
        timestamp=ts, server="223.5.5.5", name="example.com", qtype=QTYPE_A,
        status=STATUS_TIMEOUT, timeout_ms=2000, attempts=3)
    check("异常状态默认判定为异常（防止漏写异常日志）",
          implicit.verdict == dns_query.VERDICT_ANOMALY,
          "实际: %s" % implicit.verdict)


def test_engine_offline():
    section("调度引擎：离线运行与优雅停止")
    import monitor_engine as engine
    import config as cfg_mod

    conf = cfg_mod.default_config()
    conf["interval_seconds"] = 1
    conf["timeout_seconds"] = 0.3
    conf["retries"] = 0
    # 指向黑洞地址，确保离线可复现超时
    conf["dns_servers"] = ["192.0.2.1"]
    conf["domains"] = [{"name": "example.com", "enabled": True,
                        "expected_ips": [], "alert_on_change": False}]

    import queue
    out = queue.Queue()
    eng = engine.MonitorEngine(conf, out)
    eng.start()
    check("引擎已启动", eng.is_running())

    collected = []
    deadline = time.time() + 6.0
    while time.time() < deadline and len(collected) < 2:
        try:
            collected.append(out.get(timeout=0.5))
        except queue.Empty:
            pass

    eng.stop(timeout=3.0)
    check("引擎已停止", not eng.is_running())
    check("收到解析结果（黑洞地址应为超时）", len(collected) >= 1,
          "实际收到 %d 条" % len(collected))
    if collected:
        check("黑洞地址被判定为超时",
              collected[0].status == STATUS_TIMEOUT,
              "实际: %s" % collected[0].status)

    stats = eng.stats()
    check("引擎统计可用", "rounds" in stats and "queries" in stats,
          "实际: %s" % stats)


def test_engine_concurrency_floor():
    section("调度引擎：并发下限校验")
    import monitor_engine as engine
    import config as cfg_mod
    conf = cfg_mod.default_config()
    conf["max_workers"] = 1
    conf["dns_servers"] = ["1.1.1.1", "8.8.8.8"]
    conf["domains"] = [{"name": "a.com"}, {"name": "b.com"}, {"name": "c.com"}]
    effective = engine.effective_workers(conf)
    check("并发数被提升到不低于任务数", effective >= 6,
          "实际: %s" % effective)


# ---------------------------------------------------------------- 联网用例

def test_network_live():
    section("联网用例（真实 DNS 查询）")
    server = "223.5.5.5"
    result = query_server(server, "www.baidu.com", timeout=2.0, retries=2)
    if result.status == STATUS_TIMEOUT:
        skip("真实域名解析", "网络不可达（超时）")
        return
    check("真实域名解析成功或给出明确状态",
          result.status in (STATUS_OK, STATUS_EMPTY, STATUS_NXDOMAIN,
                            dns_query.STATUS_RCODE_ERROR,
                            dns_query.STATUS_NETWORK),
          "实际: %s" % result.status)
    if result.status == STATUS_OK:
        check("解析出至少一个 IP", len(result.ips) >= 1,
              "实际: %s" % result.ips)
        check("耗时被记录", result.elapsed_ms > 0,
              "实际: %s" % result.elapsed_ms)

    # 黑洞地址必须超时（这是监控程序要捕捉的核心场景）
    black = query_server("192.0.2.1", "www.baidu.com", timeout=0.5, retries=0)
    check("黑洞地址判为超时", black.status == STATUS_TIMEOUT,
          "实际: %s" % black.status)
    check("超时记录含重试次数", black.attempts == 1,
          "实际: %s" % black.attempts)

    # 不存在的域名
    nx = query_server(server, "no-such-domain-xyzabc12345.com",
                      timeout=2.0, retries=2)
    if nx.status == STATUS_TIMEOUT:
        skip("NXDOMAIN 实测", "网络不可达（超时）")
    else:
        check("不存在域名判为 NXDOMAIN", nx.status == STATUS_NXDOMAIN,
              "实际: %s (rcode=%s)" % (nx.status, nx.rcode_name))


# ---------------------------------------------------------------- 兼容性闸门

def test_py38_compat():
    section("Python 3.8 兼容性闸门")
    here = os.path.dirname(os.path.abspath(__file__))
    files = sorted(f for f in os.listdir(here)
                   if f.endswith(".py") and not f.startswith("_"))
    check("找到待检查的源文件", len(files) >= 5, "实际: %s" % files)

    # ast 能拦 match/except*，但拦不住 int|None 注解，需正则补充
    union_annotation = re.compile(
        r":\s*[A-Za-z_][\w\.\[\], ]*\s*\|\s*[A-Za-z_]")
    arrow_union = re.compile(r"->\s*[A-Za-z_][\w\.\[\], ]*\s*\|\s*[A-Za-z_]")
    builtin_generics = re.compile(
        r":\s*(list|dict|set|tuple|frozenset)\[")

    for name in files:
        path = os.path.join(here, name)
        with io.open(path, encoding="utf-8") as handle:
            source = handle.read()

        try:
            ast.parse(source, feature_version=(3, 8))
            syntax_ok = True
            syntax_detail = ""
        except SyntaxError as exc:
            syntax_ok = False
            syntax_detail = "第 %s 行: %s" % (exc.lineno, exc.msg)
        check("%s 语法兼容 3.8" % name, syntax_ok, syntax_detail)

        if name == "selftest.py":
            continue  # 自检自身允许使用较新的写法
        for label, pattern in (("联合类型注解", union_annotation),
                               ("返回值联合类型", arrow_union),
                               ("内置泛型下标", builtin_generics)):
            match = pattern.search(source)
            check("%s 无 %s" % (name, label), match is None,
                  "命中: %s" % (match.group(0).strip() if match else ""))


# ---------------------------------------------------------------- 主流程

def main():
    offline_only = "--offline" in sys.argv

    print("DNS 监控程序自检")
    print("Python %s" % sys.version.split()[0])
    print("目录: %s" % os.path.dirname(os.path.abspath(__file__)))
    if offline_only:
        print("模式: 仅离线用例")

    test_encode_name()
    test_build_query()
    test_parse_roundtrip()
    test_parse_cname_compression()
    test_parse_errors()
    test_rcode_status_mapping()
    test_format_line()
    test_format_consistency()
    test_config()
    test_config_validation()
    test_app_dir()
    test_log_writer()
    test_log_writer_backpressure()
    test_rules()
    test_ui_status_consistency()
    test_engine_offline()
    test_engine_concurrency_floor()
    test_py38_compat()
    if not offline_only:
        test_network_live()

    print("\n" + "=" * 56)
    print("通过 %d 项，失败 %d 项，跳过 %d 项" %
          (len(_PASSED), len(_FAILED), len(_SKIPPED)))
    if _FAILED:
        print("\n失败明细:")
        for label, detail in _FAILED:
            print("  - %s  %s" % (label, detail))
    print("=" * 56)
    return 1 if _FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
