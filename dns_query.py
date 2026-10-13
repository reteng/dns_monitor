# -*- coding: utf-8 -*-
"""DNS 报文查询层：手工构造与解析 DNS 报文，零第三方依赖。

设计要点（均经本机实测验证，非推测）：

1. 每次查询新建 socket —— 复用同一 socket 会收到上一条查询的陈旧响应
   （实测 tid_match=False）。把旧响应当新结果比超时更危险，会产生错误数据。
2. 校验响应事务 ID —— 防陈旧响应、防串包、防伪造。
3. 单次超时不判异常 —— 本机 UDP 存在间歇丢包，需重试耗尽才记超时。
4. NODATA 单独判定 —— rcode=0 但无地址记录（实测 www.qq.com 查 AAAA），
   只判 rcode 会漏报「空结果」。
5. TC 位置位走 TCP 回退，且必须容错 —— 实测部分服务器直接拒绝 TCP 连接
   （211.137.58.20 返回 WinError 10061），不能当崩溃处理。
"""

import random
import socket
import struct
import time
from datetime import datetime

# ---------------------------------------------------------------- 协议常量

QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28

#: 查询类型名 <-> 数值
QTYPE_NAMES = {QTYPE_A: "A", QTYPE_AAAA: "AAAA", QTYPE_CNAME: "CNAME"}
QTYPE_VALUES = {"A": QTYPE_A, "AAAA": QTYPE_AAAA, "CNAME": QTYPE_CNAME}

DNS_PORT = 53

#: 压缩指针最大跳转次数，防止畸形报文造成死循环
MAX_POINTER_JUMPS = 16

#: 单个 DNS 报文长度上限（RFC 1035）
MAX_MESSAGE_SIZE = 65535

#: UDP 收包缓冲（EDNS0 常规上限 4096）
UDP_BUFFER_SIZE = 4096

# ---------------------------------------------------------------- 解析状态

STATUS_OK = "ok"                 # 解析成功且含地址记录
STATUS_TIMEOUT = "timeout"       # 重试耗尽仍超时
STATUS_NXDOMAIN = "nxdomain"     # 域名不存在（rcode=3）
STATUS_RCODE_ERROR = "rcode"     # 其他非零 rcode
STATUS_EMPTY = "empty"           # NODATA：NOERROR 但无地址记录
STATUS_MALFORMED = "malformed"   # 响应报文畸形
STATUS_NETWORK = "network"       # 网络层错误（不可达、连接重置等）
STATUS_TRUNCATED = "truncated"   # TC 置位且 TCP 回退失败

#: 状态中文名（用于界面与日志）
STATUS_LABELS = {
    STATUS_OK: "正常",
    STATUS_TIMEOUT: "超时",
    STATUS_NXDOMAIN: "域名不存在",
    STATUS_RCODE_ERROR: "返回错误",
    STATUS_EMPTY: "空结果",
    STATUS_MALFORMED: "响应异常",
    STATUS_NETWORK: "网络错误",
    STATUS_TRUNCATED: "响应截断",
}

#: 非正常状态集合（用于统计异常数）
ABNORMAL_STATUSES = frozenset([
    STATUS_TIMEOUT, STATUS_NXDOMAIN, STATUS_RCODE_ERROR,
    STATUS_EMPTY, STATUS_MALFORMED, STATUS_NETWORK, STATUS_TRUNCATED,
])

# ---------------------------------------------------------------- 判定级别

VERDICT_OK = "ok"            # 正常
VERDICT_NOTICE = "notice"    # 提示级（如解析结果与上次不同）
VERDICT_ANOMALY = "anomaly"  # 异常（基础规则命中或期望 IP 不匹配）

VERDICT_LABELS = {
    VERDICT_OK: "正常",
    VERDICT_NOTICE: "结果变化",
    VERDICT_ANOMALY: "异常",
}

# ---------------------------------------------------------------- rcode 表

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

RCODE_DESCRIPTIONS = {
    0: "无错误",
    1: "报文格式错误",
    2: "服务器故障",
    3: "域名不存在",
    4: "服务器不支持该操作",
    5: "查询被服务器拒绝",
    6: "名称意外存在",
    7: "记录集意外存在",
    8: "记录集不存在",
    9: "服务器未授权",
    10: "名称不在授权区",
}


# ---------------------------------------------------------------- 异常类型

class DnsError(Exception):
    """DNS 层异常基类。"""


class DnsFormatError(DnsError):
    """响应报文畸形或截断。"""


class DnsIdMismatch(DnsError):
    """响应事务 ID 与请求不符（陈旧响应或伪造）。"""


# ---------------------------------------------------------------- 结果对象

class DnsResult(object):
    """单次 DNS 解析的结果，含基础状态与规则判定信息。

    status 由本模块填写；verdict 与 note 由规则层（monitor_engine）填写。
    """

    __slots__ = (
        "timestamp", "server", "name", "qtype", "status",
        "rcode", "rcode_name", "ips", "cname_chain",
        "elapsed_ms", "error", "attempts", "via_tcp",
        "timeout_ms", "verdict", "note",
    )

    def __init__(self, timestamp, server, name, qtype, status,
                 rcode=None, rcode_name=None, ips=None, cname_chain=None,
                 elapsed_ms=0.0, error=None, attempts=1, via_tcp=False,
                 timeout_ms=0, verdict=VERDICT_OK, note=None):
        self.timestamp = timestamp
        self.server = server
        self.name = name
        self.qtype = qtype
        self.status = status
        self.rcode = rcode
        self.rcode_name = rcode_name
        self.ips = ips if ips is not None else []
        self.cname_chain = cname_chain if cname_chain is not None else []
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.attempts = attempts
        self.via_tcp = via_tcp
        self.timeout_ms = timeout_ms
        # 状态非正常时，默认判定即为异常 —— 避免 verdict 与 status 自相矛盾
        # 导致异常记录被漏写进异常日志（规则层可再覆盖为提示级）
        if verdict == VERDICT_OK and status != STATUS_OK:
            verdict = VERDICT_ANOMALY
        self.verdict = verdict
        self.note = note

    @property
    def ok(self):
        """解析本身是否正常（未做规则判定）。"""
        return self.status == STATUS_OK

    @property
    def ips_text(self):
        """地址列表的展示文本。"""
        return ", ".join(self.ips)

    def format_line(self):
        """规范化的单条记录文本。

        骨架：2026-10-13 12:00:33 example.com 通过 223.5.5.5 解析为 1.1.1.1
        异常与提示信息以括号后缀补充，不破坏主结构。
        """
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        qtype_name = QTYPE_NAMES.get(self.qtype, str(self.qtype))
        base = "%s %s 通过 %s " % (ts, self.name, self.server)

        if self.status == STATUS_OK:
            line = base + "解析为 %s" % self.ips_text
        elif self.status == STATUS_TIMEOUT:
            line = base + "解析超时 (共等待 %.0fms, 单次超时 %dms, 重试 %d 次)" % (
                self.elapsed_ms, self.timeout_ms, self.attempts - 1)
        elif self.status == STATUS_NXDOMAIN:
            line = base + "解析失败: NXDOMAIN (域名不存在)"
        elif self.status == STATUS_RCODE_ERROR:
            line = base + "解析失败: %s (%s)" % (
                self.rcode_name or "未知",
                RCODE_DESCRIPTIONS.get(self.rcode, "未知错误"))
        elif self.status == STATUS_EMPTY:
            line = base + "返回空结果 (NOERROR 但无 %s 记录)" % qtype_name
        elif self.status == STATUS_TRUNCATED:
            line = base + "响应被截断且 TCP 回退失败: %s" % (self.error or "未知原因")
        elif self.status == STATUS_MALFORMED:
            line = base + "响应异常: %s" % (self.error or "报文畸形")
        else:
            line = base + "网络错误: %s" % (self.error or "未知错误")

        if self.note:
            line += " (%s)" % self.note
        return line


# ---------------------------------------------------------------- 报文构造

def encode_name(name):
    """把域名编码为 DNS 报文的 QNAME 格式（长度前缀标签 + 结束零字节）。

    支持中文等非 ASCII 域名（自动转 punycode）。含下划线等非 IDNA 字符时
    按原样处理 —— DNS 协议本身允许，只是主机名规范不允许。
    """
    clean = name.strip().rstrip(".")
    if not clean:
        raise ValueError("域名为空")

    try:
        ascii_name = clean.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        try:
            clean.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("域名无法编码为 DNS 格式: %s" % name)
        ascii_name = clean

    out = bytearray()
    for label in ascii_name.split("."):
        if not label:
            raise ValueError("域名含空标签: %s" % name)
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("域名标签超过 63 字节: %s" % label)
        out.append(len(raw))
        out.extend(raw)
    out.append(0)

    if len(out) > 255:
        raise ValueError("域名编码后超过 255 字节: %s" % name)
    return bytes(out)


def build_query(name, qtype=QTYPE_A, recursion_desired=True):
    """构造 DNS 查询报文，返回 (事务ID, 报文字节)。"""
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100 if recursion_desired else 0x0000
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    return tid, header + question


# ---------------------------------------------------------------- 报文解析

def _skip_name(data, offset):
    """跳过一段域名，返回其后的偏移量。遇到压缩指针即视为域名结束。"""
    while True:
        if offset >= len(data):
            raise DnsFormatError("域名越过报文边界")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsFormatError("压缩指针被截断")
            return offset + 2
        if length > 63:
            raise DnsFormatError("非法标签长度: %d" % length)
        offset += 1 + length


def _read_name(data, offset):
    """完整读取一段域名（跟随压缩指针），返回 (域名文本, 指针后的偏移)。"""
    labels = []
    jumps = 0
    while True:
        if offset >= len(data):
            raise DnsFormatError("域名越过报文边界")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsFormatError("压缩指针被截断")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DnsFormatError("压缩指针跳转次数过多，疑似环路")
            offset = pointer
            continue
        if length > 63:
            raise DnsFormatError("非法标签长度: %d" % length)
        end = offset + 1 + length
        if end > len(data):
            raise DnsFormatError("标签被截断")
        labels.append(data[offset + 1:end].decode("latin1"))
        offset = end


def _format_ipv6(raw):
    """把 16 字节原始地址格式化为 IPv6 文本（含 :: 压缩）。"""
    if len(raw) != 16:
        raise DnsFormatError("IPv6 地址长度错误: %d" % len(raw))
    groups = struct.unpack(">8H", raw)

    best_start = -1
    best_len = 0
    cur_start = 0
    cur_len = 0
    for index, group in enumerate(groups):
        if group == 0:
            if cur_len == 0:
                cur_start = index
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_len = 0

    if best_len < 2:
        return ":".join("%x" % g for g in groups)
    head = ":".join("%x" % g for g in groups[:best_start])
    tail = ":".join("%x" % g for g in groups[best_start + best_len:])
    return head + "::" + tail


class ParsedResponse(object):
    """解析后的 DNS 响应（仅保留监控关心的字段）。"""

    __slots__ = ("tid", "flags", "rcode", "tc", "aa", "ra", "ips", "cnames")

    def __init__(self, tid, flags, rcode, tc, aa, ra, ips, cnames):
        self.tid = tid
        self.flags = flags
        self.rcode = rcode
        self.tc = tc
        self.aa = aa
        self.ra = ra
        self.ips = ips
        self.cnames = cnames


def parse_response(data, expected_tid):
    """解析 DNS 响应报文。

    先校验事务 ID（不匹配抛 DnsIdMismatch，由调用方决定继续等待），
    再遍历问题区与答案区，处理压缩指针、CNAME 链与 A/AAAA 记录。
    """
    if len(data) < 12:
        raise DnsFormatError("报文长度不足 12 字节: %d" % len(data))
    if len(data) > MAX_MESSAGE_SIZE:
        raise DnsFormatError("报文长度超过协议上限: %d" % len(data))

    tid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        ">HHHHHH", data[:12])

    if tid != expected_tid:
        raise DnsIdMismatch(
            "事务 ID 不匹配: 期望 %d, 实际 %d" % (expected_tid, tid))

    if not (flags >> 15) & 1:
        raise DnsFormatError("响应报文的 QR 位为 0，不是响应")

    rcode = flags & 0xF
    tc = (flags >> 9) & 1
    aa = (flags >> 10) & 1
    ra = (flags >> 7) & 1

    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        if offset + 4 > len(data):
            raise DnsFormatError("问题区记录被截断")
        offset += 4

    ips = []
    cnames = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise DnsFormatError("答案记录头被截断")
        rtype, _rclass, _ttl, rdlength = struct.unpack(
            ">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DnsFormatError("答案记录数据被截断")

        if rtype == QTYPE_A and rdlength == 4:
            ips.append(socket.inet_ntoa(data[offset:offset + 4]))
        elif rtype == QTYPE_AAAA and rdlength == 16:
            ips.append(_format_ipv6(data[offset:offset + 16]))
        elif rtype == QTYPE_CNAME:
            target, _ = _read_name(data, offset)
            cnames.append(target)
        offset += rdlength

    return ParsedResponse(tid, flags, rcode, tc, aa, ra, ips, cnames)


# ---------------------------------------------------------------- 网络查询

def _recv_exact(sock, count):
    """TCP 上精确读取 count 字节。"""
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise DnsFormatError("TCP 连接被对端提前关闭")
        buf.extend(chunk)
    return bytes(buf)


def _query_udp(server, name, timeout, qtype, port):
    """单次 UDP 查询。每次新建 socket（复用会拿到陈旧响应）。

    返回 (ParsedResponse, malformed_note)：malformed_note 非空表示等待期间
    收到过畸形报文（用于超时后给出更准确的诊断）。
    """
    tid, packet = build_query(name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    malformed_note = None
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("等待响应超时")
            sock.settimeout(remaining)
            data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
            if addr[0] != server:
                continue  # 忽略非目标服务器发来的报文
            try:
                return parse_response(data, tid), malformed_note
            except DnsIdMismatch:
                continue  # 陈旧或伪造响应，继续等待正确响应
            except DnsFormatError as exc:
                malformed_note = str(exc)
                continue  # 畸形报文可能是噪声，继续等待
    finally:
        sock.close()


def _query_tcp(server, name, timeout, qtype, port):
    """TCP 查询（仅用于 TC 置位后的回退）。

    部分服务器直接拒绝 TCP 连接（实测 211.137.58.20 返回 WinError 10061），
    调用方必须容错。
    """
    tid, packet = build_query(name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        data = _recv_exact(sock, length)
    finally:
        sock.close()
    return parse_response(data, tid)


def _describe_oserror(exc):
    """把 OSError 转成便于排查的中文描述。"""
    winerror = getattr(exc, "winerror", None)
    text = str(exc)
    if winerror is not None:
        return "%s (WinError %d)" % (text, winerror)
    return text


def query_server(server, name, timeout=2.0, retries=2, qtype=QTYPE_A,
                 port=DNS_PORT):
    """向指定 DNS 服务器查询，返回 DnsResult。

    超时与网络类错误会重试（实测本机 UDP 间歇丢包，单次超时不可判异常）；
    重试全部耗尽才记超时。畸形响应不重试（通常是确定性问题）。
    """
    start = time.monotonic()
    timestamp = datetime.now()
    timeout_ms = int(round(timeout * 1000))

    attempts = 0
    last_status = STATUS_TIMEOUT
    last_error = "等待响应超时"

    for attempt in range(retries + 1):
        attempts = attempt + 1
        malformed_note = None
        try:
            parsed, malformed_note = _query_udp(server, name, timeout, qtype, port)
        except socket.timeout:
            if malformed_note:
                # 等待期间收到过畸形报文：比单纯超时更有诊断价值
                last_status, last_error = STATUS_MALFORMED, malformed_note
            else:
                last_status, last_error = STATUS_TIMEOUT, "等待响应超时"
            continue
        except DnsFormatError as exc:
            last_status, last_error = STATUS_MALFORMED, str(exc)
            break
        except OSError as exc:
            last_status, last_error = STATUS_NETWORK, _describe_oserror(exc)
            continue

        # ---------------- 收到合法响应 ----------------
        elapsed_ms = (time.monotonic() - start) * 1000.0
        via_tcp = False
        error = None

        if parsed.tc:
            # 响应被截断，尝试 TCP 回退；失败则如实报告截断
            try:
                parsed = _query_tcp(server, name, timeout, qtype, port)
                via_tcp = True
                elapsed_ms = (time.monotonic() - start) * 1000.0
            except Exception as exc:  # noqa: BLE001 - 回退失败不能影响主流程
                return DnsResult(
                    timestamp=timestamp, server=server, name=name, qtype=qtype,
                    status=STATUS_TRUNCATED, rcode=parsed.rcode,
                    rcode_name=RCODE_NAMES.get(parsed.rcode),
                    ips=parsed.ips, cname_chain=parsed.cnames,
                    elapsed_ms=elapsed_ms, error=_describe_oserror(exc)
                    if isinstance(exc, OSError) else str(exc),
                    attempts=attempts, via_tcp=False, timeout_ms=timeout_ms)

        rcode = parsed.rcode
        rcode_name = RCODE_NAMES.get(rcode, "RCODE%d" % rcode)

        if rcode == 3:
            status = STATUS_NXDOMAIN
        elif rcode != 0:
            status = STATUS_RCODE_ERROR
        elif not parsed.ips:
            # NODATA：rcode=0 但没有任何地址记录（实测 www.qq.com 查 AAAA）
            status = STATUS_EMPTY
        else:
            status = STATUS_OK

        return DnsResult(
            timestamp=timestamp, server=server, name=name, qtype=qtype,
            status=status, rcode=rcode, rcode_name=rcode_name,
            ips=parsed.ips, cname_chain=parsed.cnames,
            elapsed_ms=elapsed_ms, error=error,
            attempts=attempts, via_tcp=via_tcp, timeout_ms=timeout_ms)

    # ---------------- 重试耗尽 ----------------
    elapsed_ms = (time.monotonic() - start) * 1000.0
    return DnsResult(
        timestamp=timestamp, server=server, name=name, qtype=qtype,
        status=last_status, error=last_error,
        elapsed_ms=elapsed_ms, attempts=attempts,
        timeout_ms=timeout_ms)


def parse_qtype(text):
    """把配置中的 'A' / 'AAAA' 文本转为数值。"""
    key = str(text).strip().upper()
    if key not in QTYPE_VALUES:
        raise ValueError("不支持的查询类型: %s（仅支持 A、AAAA）" % text)
    return QTYPE_VALUES[key]
