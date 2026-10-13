# -*- coding: utf-8 -*-
"""配置读写与系统环境探测。

路径解析要点（实测踩过的坑）：任务计划程序启动时 cwd 常为
C:\\Windows\\System32，相对路径会解析到无写权限位置导致日志静默失败。
所有相对路径一律相对 app_dir() 解析，绝不用 os.getcwd()。
"""

import ipaddress
import json
import os
import re
import sys
import tempfile

CONFIG_FILENAME = "config.json"

#: 默认日志目录（相对 app_dir）
DEFAULT_LOG_DIR = "logs"

#: 域名校验：允许字母数字连字符，各级标签 1-63 字符，至少两级
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")

#: 配置边界值（防止用户填入极端值导致程序不可用）
LIMITS = {
    "interval_seconds": (1, 86400),
    "timeout_seconds": (0.1, 60.0),
    "retries": (0, 10),
    "max_workers": (1, 64),
    "max_rows": (100, 200000),
    "refresh_ms": (50, 5000),
    "font_size": (7, 24),
}


def app_dir():
    """程序所在目录。

    打包运行用 exe 所在目录 —— 不能用 sys._MEIPASS，那是临时解压目录，
    写进去的日志会被清理。源码运行用脚本所在目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def default_config_path():
    return os.path.join(app_dir(), CONFIG_FILENAME)


def resolve_log_dir(log_dir):
    """把配置中的日志目录解析为绝对路径（相对 app_dir 而非 cwd）。"""
    if not log_dir:
        log_dir = DEFAULT_LOG_DIR
    if os.path.isabs(log_dir):
        return os.path.normpath(log_dir)
    return os.path.normpath(os.path.join(app_dir(), log_dir))


# ---------------------------------------------------------------- 校验工具

def is_valid_ip(text):
    """校验 IPv4 / IPv6 地址文本。"""
    if not text:
        return False
    try:
        ipaddress.ip_address(str(text).strip())
        return True
    except ValueError:
        return False


def is_valid_domain(name):
    """校验域名。允许 IDNA（中文域名），要求至少两级标签。"""
    if not name:
        return False
    text = str(name).strip().rstrip(".")
    if not text or len(text) > 253:
        return False
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    labels = ascii_name.split(".")
    if len(labels) < 2:
        return False
    return all(_DOMAIN_LABEL.match(label) for label in labels)


def is_valid_server(text):
    """校验 DNS 服务器地址。允许 'IP' 或 'IP#端口' 两种写法。"""
    if not text:
        return False
    raw = str(text).strip()
    if "#" in raw:
        host, _, port_text = raw.partition("#")
        if not port_text.isdigit():
            return False
        port = int(port_text)
        if not (1 <= port <= 65535):
            return False
        return is_valid_ip(host)
    return is_valid_ip(raw)


def parse_server(text):
    """把 'IP' 或 'IP#端口' 解析为 (IP, 端口)。"""
    raw = str(text).strip()
    if "#" in raw:
        host, _, port_text = raw.partition("#")
        return host.strip(), int(port_text)
    return raw, 53


# ---------------------------------------------------------------- 默认配置

def default_config():
    """内置默认配置。"""
    return {
        "interval_seconds": 30,
        "timeout_seconds": 2.0,
        "retries": 2,
        "query_type": "A",
        "max_workers": 8,
        "log_dir": DEFAULT_LOG_DIR,
        "log_all": True,
        "dns_servers": ["223.5.5.5", "8.8.8.8"],
        "domains": [
            {"name": "example.com", "enabled": True,
             "expected_ips": [], "alert_on_change": True},
        ],
        "ui": {
            "max_rows": 5000,
            "refresh_ms": 150,
            "font_family": "",
            "font_size": 10,
        },
    }


def _clamp_number(value, key, cast, default):
    """把数值裁剪到合法区间；无法转换时回退默认值。"""
    low, high = LIMITS[key]
    try:
        number = cast(value)
    except (TypeError, ValueError):
        return cast(default)
    if number < low:
        return cast(low)
    if number > high:
        return cast(high)
    return number


def _normalize_domain(entry):
    """规整单个域名配置项；非法项返回 None 由调用方剔除。"""
    if isinstance(entry, str):
        entry = {"name": entry}
    if not isinstance(entry, dict):
        return None

    name = str(entry.get("name", "")).strip().rstrip(".")
    if not is_valid_domain(name):
        return None

    raw_ips = entry.get("expected_ips", [])
    if isinstance(raw_ips, str):
        raw_ips = re.split(r"[,\s;]+", raw_ips)
    if not isinstance(raw_ips, (list, tuple)):
        raw_ips = []

    expected = []
    for item in raw_ips:
        text = str(item).strip()
        if text and is_valid_ip(text) and text not in expected:
            expected.append(text)

    return {
        "name": name,
        "enabled": bool(entry.get("enabled", True)),
        "expected_ips": expected,
        "alert_on_change": bool(entry.get("alert_on_change", True)),
    }


def normalize_config(raw):
    """把任意来源的配置规整为合法配置。

    非法项被静默剔除而非报错 —— 配置损坏时程序仍应能启动。
    """
    defaults = default_config()
    if not isinstance(raw, dict):
        return defaults

    conf = {}

    conf["interval_seconds"] = _clamp_number(
        raw.get("interval_seconds", defaults["interval_seconds"]),
        "interval_seconds", int, defaults["interval_seconds"])
    conf["timeout_seconds"] = _clamp_number(
        raw.get("timeout_seconds", defaults["timeout_seconds"]),
        "timeout_seconds", float, defaults["timeout_seconds"])
    conf["retries"] = _clamp_number(
        raw.get("retries", defaults["retries"]),
        "retries", int, defaults["retries"])
    conf["max_workers"] = _clamp_number(
        raw.get("max_workers", defaults["max_workers"]),
        "max_workers", int, defaults["max_workers"])

    qtype = str(raw.get("query_type", defaults["query_type"])).strip().upper()
    conf["query_type"] = qtype if qtype in ("A", "AAAA") else "A"

    log_dir = str(raw.get("log_dir", defaults["log_dir"])).strip()
    conf["log_dir"] = log_dir or DEFAULT_LOG_DIR
    conf["log_all"] = bool(raw.get("log_all", defaults["log_all"]))

    # DNS 服务器：去重 + 剔除非法项
    servers = raw.get("dns_servers", defaults["dns_servers"])
    if isinstance(servers, str):
        servers = re.split(r"[,\s;]+", servers)
    if not isinstance(servers, (list, tuple)):
        servers = defaults["dns_servers"]
    clean_servers = []
    for item in servers:
        text = str(item).strip()
        if text and is_valid_server(text) and text not in clean_servers:
            clean_servers.append(text)
    conf["dns_servers"] = clean_servers or list(defaults["dns_servers"])

    # 域名：去重 + 剔除非法项
    domains = raw.get("domains", defaults["domains"])
    if not isinstance(domains, (list, tuple)):
        domains = defaults["domains"]
    clean_domains = []
    seen = set()
    for entry in domains:
        item = _normalize_domain(entry)
        if item is None:
            continue
        key = item["name"].lower()
        if key in seen:
            continue
        seen.add(key)
        clean_domains.append(item)
    conf["domains"] = clean_domains or [dict(d) for d in defaults["domains"]]

    # 界面设置
    ui_raw = raw.get("ui", {})
    if not isinstance(ui_raw, dict):
        ui_raw = {}
    ui_defaults = defaults["ui"]
    conf["ui"] = {
        "max_rows": _clamp_number(
            ui_raw.get("max_rows", ui_defaults["max_rows"]),
            "max_rows", int, ui_defaults["max_rows"]),
        "refresh_ms": _clamp_number(
            ui_raw.get("refresh_ms", ui_defaults["refresh_ms"]),
            "refresh_ms", int, ui_defaults["refresh_ms"]),
        "font_family": str(ui_raw.get("font_family", "")).strip(),
        "font_size": _clamp_number(
            ui_raw.get("font_size", ui_defaults["font_size"]),
            "font_size", int, ui_defaults["font_size"]),
    }

    return conf


# ---------------------------------------------------------------- 读写

def load_config(path=None):
    """读取配置。文件不存在或损坏时返回默认配置，不抛异常。"""
    path = path or default_config_path()
    if not os.path.isfile(path):
        return default_config()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (ValueError, OSError, UnicodeDecodeError):
        return default_config()
    return normalize_config(raw)


def load_config_with_status(path=None):
    """读取配置，同时返回诊断信息（供界面提示用）。

    返回 (配置, 提示文本)；提示为空表示一切正常。
    """
    path = path or default_config_path()
    if not os.path.isfile(path):
        return default_config(), "配置文件不存在，已使用默认配置"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        return default_config(), "配置文件无法解析（%s），已使用默认配置" % exc
    return normalize_config(raw), ""


def save_config(conf, path=None):
    """原子写入配置：先写临时文件再替换，避免写入中途断电损坏配置。"""
    path = path or default_config_path()
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)

    normalized = normalize_config(conf)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".tmp",
        dir=directory or None, delete=False)
    try:
        with handle:
            json.dump(normalized, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(handle.name, path)
    except Exception:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    return path


# ---------------------------------------------------------------- 环境探测

def detect_system_dns_servers():
    """从注册表读取本机配置的 DNS 服务器。

    读取 NameServer（静态）与 DhcpNameServer（DHCP 下发）两类键，
    值可能是空格或逗号分隔的多个地址。仅 Windows 可用。
    """
    if sys.platform != "win32":
        return []

    try:
        import winreg
    except ImportError:
        return []

    servers = []
    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    except OSError:
        return []

    try:
        index = 0
        while True:
            try:
                sub_name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1

            try:
                sub = winreg.OpenKey(root, sub_name)
            except OSError:
                continue
            try:
                for value_name in ("NameServer", "DhcpNameServer"):
                    try:
                        value, _ = winreg.QueryValueEx(sub, value_name)
                    except (FileNotFoundError, OSError):
                        continue
                    if not value:
                        continue
                    for token in re.split(r"[,\s]+", str(value)):
                        token = token.strip()
                        if token and is_valid_ip(token) and token not in servers:
                            servers.append(token)
            finally:
                winreg.CloseKey(sub)
    finally:
        winreg.CloseKey(root)

    return servers


def validate_config(conf):
    """启动前校验配置，返回问题列表（空列表表示可启动）。"""
    problems = []
    if not conf.get("dns_servers"):
        problems.append("未配置任何 DNS 服务器")
    active = [d for d in conf.get("domains", []) if d.get("enabled", True)]
    if not active:
        problems.append("未启用任何监控域名")
    return problems
