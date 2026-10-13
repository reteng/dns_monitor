# -*- coding: utf-8 -*-
"""tkinter/ttk 图形界面：实时监控面板与配置页。

不卡顿的关键设计（实测单帧最大 6.5ms，远低于 ~100ms 卡顿阈值）：
- 工作线程只往队列投递，界面用 after() 定时批量排空
- Treeview 批量插入，超限时一次性删除头部（实测删 500 行 0.8ms）
- 统计标签同 tick 节流刷新，绝不逐行更新
- 仅在用户停留底部时自动跟随最新，回看历史不被打断
"""

import os
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import config as config_mod
import dns_query
import log_writer
import monitor_engine

#: 单次刷新最多处理的行数，防止单帧过长
MAX_BATCH_PER_TICK = 2000

#: 字体回退链（实测本机 SimHei 缺失，Microsoft YaHei UI 可用）
FONT_FALLBACKS = ("Microsoft YaHei UI", "Microsoft YaHei",
                  "Segoe UI", "Tahoma")

#: 颜色规则：异常红、提示黄、正常默认
COLOR_ANOMALY = "#ffd6d6"
COLOR_NOTICE = "#fff4cc"
COLOR_ERROR_TEXT = "#b00020"

STATUS_TEXT = dns_query.STATUS_LABELS
VERDICT_TEXT = dns_query.VERDICT_LABELS


def pick_font_family(root, preferred=""):
    """按回退链挑选可用字体。"""
    try:
        from tkinter import font as tkfont
        available = set(tkfont.families(root))
    except Exception:
        return preferred or "TkDefaultFont"

    if preferred and preferred in available:
        return preferred
    for name in FONT_FALLBACKS:
        if name in available:
            return name
    return "TkDefaultFont"


class MonitorTab(object):
    """实时监控页：工具栏 + 统计条 + 记录表 + 状态栏。"""

    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent, padding=6)
        self._build_toolbar()
        self._build_stats()
        self._build_table()
        self._build_statusbar()

    # ------------------------------------------------ 布局

    def _build_toolbar(self):
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x", pady=(0, 6))

        self.start_button = ttk.Button(bar, text="启动监测",
                                       command=self.app.on_start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(bar, text="停止监测", state="disabled",
                                      command=self.app.on_stop)
        self.stop_button.pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=8)
        ttk.Button(bar, text="清空记录", command=self.clear).pack(side="left")
        ttk.Button(bar, text="导出记录", command=self.export).pack(
            side="left", padx=4)
        ttk.Button(bar, text="打开日志目录",
                   command=self.app.open_log_dir).pack(side="left")

        self.autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="自动滚动", variable=self.autoscroll).pack(
            side="right")

    def _build_stats(self):
        box = ttk.LabelFrame(self.frame, text="统计", padding=6)
        box.pack(fill="x", pady=(0, 6))

        self.stat_labels = {}
        specs = (("rounds", "监测轮次"), ("queries", "总查询数"),
                 ("anomalies", "异常数"), ("notices", "变化提示"),
                 ("rate", "正常率"), ("last", "最后更新"))
        for index, (key, title) in enumerate(specs):
            cell = ttk.Frame(box)
            cell.grid(row=0, column=index, padx=(0, 18), sticky="w")
            ttk.Label(cell, text=title, foreground="#666666").pack(anchor="w")
            label = ttk.Label(cell, text="—", font=(self.app.font_family,
                                                    self.app.font_size + 1,
                                                    "bold"))
            label.pack(anchor="w")
            self.stat_labels[key] = label

    def _build_table(self):
        wrap = ttk.Frame(self.frame)
        wrap.pack(fill="both", expand=True)

        columns = ("time", "domain", "server", "result", "elapsed", "status")
        headings = {"time": "时间", "domain": "域名", "server": "DNS服务器",
                    "result": "解析结果", "elapsed": "耗时", "status": "状态"}
        widths = {"time": 150, "domain": 200, "server": 130,
                  "result": 240, "elapsed": 70, "status": 90}

        self.tree = ttk.Treeview(wrap, columns=columns, show="headings",
                                 height=18)
        for column in columns:
            self.tree.heading(column, text=headings[column])
            anchor = "e" if column == "elapsed" else "w"
            self.tree.column(column, width=widths[column], anchor=anchor,
                             stretch=(column == "result"))

        self.tree.tag_configure("anomaly", background=COLOR_ANOMALY,
                                foreground=COLOR_ERROR_TEXT)
        self.tree.tag_configure("notice", background=COLOR_NOTICE)

        scroll_y = ttk.Scrollbar(wrap, orient="vertical",
                                 command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_x = ttk.Scrollbar(wrap, orient="horizontal",
                                 command=self.tree.xview)
        self.tree.configure(xscrollcommand=scroll_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        # 双击复制整行文本，便于取证
        self.tree.bind("<Double-1>", self._copy_row)

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="就绪")
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x", pady=(6, 0))
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.pending_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.pending_var,
                  foreground="#886600").pack(side="right")

    # ------------------------------------------------ 操作

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.app.clear_counters()

    def export(self):
        """把当前表格内容导出为文本文件。"""
        items = self.tree.get_children()
        if not items:
            messagebox.showinfo("导出记录", "当前没有可导出的记录。")
            return
        path = filedialog.asksaveasfilename(
            title="导出监控记录", defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile="dns_monitor_export.txt")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for item in items:
                    values = self.tree.item(item, "values")
                    handle.write(" ".join(str(v) for v in values) + "\n")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self.status_var.set("已导出 %d 条记录到 %s" % (len(items), path))

    def _copy_row(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(" ".join(str(v) for v in values))
        self.status_var.set("已复制该行内容到剪贴板")

    # ------------------------------------------------ 数据刷新

    def append_results(self, results):
        """批量追加记录（由 App 的刷新定时器调用）。"""
        if not results:
            return
        tree = self.tree
        max_rows = self.app.max_rows

        # 插入前记录是否停在底部，用于决定是否自动跟随
        follow = self._at_bottom()

        for result in results:
            tag = ""
            if result.verdict == dns_query.VERDICT_ANOMALY:
                tag = "anomaly"
            elif result.verdict == dns_query.VERDICT_NOTICE:
                tag = "notice"

            tree.insert(
                "", "end",
                values=(result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        result.name, result.server,
                        self._result_text(result),
                        "%.0fms" % result.elapsed_ms,
                        self._status_text(result)),
                tags=(tag,) if tag else ())

        # 超限裁剪：一次性删除头部，实测删 500 行仅 0.8ms
        children = tree.get_children()
        if len(children) > max_rows:
            tree.delete(*children[:len(children) - max_rows])
            children = tree.get_children()

        if self.autoscroll.get() and follow and children:
            tree.see(children[-1])

    def _at_bottom(self):
        """判断视图是否停在底部（用于智能自动滚动）。"""
        try:
            return self.tree.yview()[1] >= 0.999
        except Exception:
            return True

    @staticmethod
    def _result_text(result):
        if result.ips:
            return ", ".join(result.ips)
        if result.status == dns_query.STATUS_TIMEOUT:
            return "—"
        if result.status in (dns_query.STATUS_NXDOMAIN,
                             dns_query.STATUS_RCODE_ERROR):
            return result.rcode_name or "—"
        return "—"

    @staticmethod
    def _status_text(result):
        # 判定结果优先于解析状态：期望 IP 不匹配时解析本身是成功的，
        # 若只显示「正常」会与红色高亮自相矛盾
        if result.verdict == dns_query.VERDICT_NOTICE:
            return "结果变化"
        if (result.verdict == dns_query.VERDICT_ANOMALY
                and result.status == dns_query.STATUS_OK):
            return "IP不符"
        return STATUS_TEXT.get(result.status, result.status)

    def update_stats(self, stats, extras):
        """刷新统计条（节流调用）。"""
        self.stat_labels["rounds"].configure(text=str(stats.get("rounds", 0)))
        self.stat_labels["queries"].configure(
            text=str(stats.get("queries", 0)))
        self.stat_labels["anomalies"].configure(
            text=str(stats.get("anomalies", 0)))
        self.stat_labels["notices"].configure(
            text=str(stats.get("notices", 0)))

        total = stats.get("queries", 0)
        anomalies = stats.get("anomalies", 0)
        rate = 100.0 if total == 0 else (total - anomalies) * 100.0 / total
        self.stat_labels["rate"].configure(text="%.1f%%" % rate)
        self.stat_labels["last"].configure(
            text=extras.get("last_update") or "—")

        dropped = stats.get("dropped", 0) + extras.get("ui_dropped", 0)
        if dropped:
            self.pending_var.set("已丢弃 %d 条（更新过快）" % dropped)
        else:
            self.pending_var.set("")

    def set_running(self, running):
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")


class ConfigTab(object):
    """配置页：域名表、参数、DNS 服务器、日志设置。"""

    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent, padding=6)
        self._build()
        self.load_from(self.app.conf)

    # ------------------------------------------------ 布局

    def _build(self):
        outer = ttk.Frame(self.frame)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=3)
        outer.columnconfigure(1, weight=2)
        outer.rowconfigure(0, weight=1)

        self._build_domains(outer)
        self._build_servers(outer)
        self._build_params(outer)
        self._build_actions(outer)

    def _build_domains(self, parent):
        box = ttk.LabelFrame(parent, text="监控域名", padding=6)
        box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)

        columns = ("enabled", "name", "expected", "change")
        self.domain_tree = ttk.Treeview(box, columns=columns, show="headings",
                                        height=10, selectmode="browse")
        for column, title, width in (("enabled", "启用", 50),
                                     ("name", "域名", 190),
                                     ("expected", "期望IP(逗号分隔)", 200),
                                     ("change", "变化提示", 70)):
            self.domain_tree.heading(column, text=title)
            self.domain_tree.column(column, width=width,
                                    anchor="center" if column != "name"
                                    else "w")
        self.domain_tree.grid(row=0, column=0, sticky="nsew")
        self.domain_tree.bind("<Double-1>", lambda e: self.edit_domain())

        scroll = ttk.Scrollbar(box, orient="vertical",
                               command=self.domain_tree.yview)
        self.domain_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        buttons = ttk.Frame(box)
        buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(buttons, text="添加", command=self.add_domain).pack(
            side="left")
        ttk.Button(buttons, text="编辑", command=self.edit_domain).pack(
            side="left", padx=4)
        ttk.Button(buttons, text="删除", command=self.remove_domain).pack(
            side="left")
        ttk.Button(buttons, text="启用/停用",
                   command=self.toggle_domain).pack(side="left", padx=4)
        ttk.Label(buttons, text="（双击可编辑）",
                  foreground="#777777").pack(side="left", padx=6)

    def _build_servers(self, parent):
        box = ttk.LabelFrame(parent, text="DNS 服务器", padding=6)
        box.grid(row=0, column=1, sticky="nsew")
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)

        self.server_list = tk.Listbox(box, height=8, exportselection=False)
        self.server_list.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(box, orient="vertical",
                               command=self.server_list.yview)
        self.server_list.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        entry_row = ttk.Frame(box)
        entry_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        entry_row.columnconfigure(0, weight=1)
        self.server_entry = ttk.Entry(entry_row)
        self.server_entry.grid(row=0, column=0, sticky="ew")
        self.server_entry.bind("<Return>", lambda e: self.add_server())
        ttk.Button(entry_row, text="添加", command=self.add_server).grid(
            row=0, column=1, padx=(4, 0))

        buttons = ttk.Frame(box)
        buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        ttk.Button(buttons, text="删除选中",
                   command=self.remove_server).pack(side="left")
        ttk.Button(buttons, text="导入系统DNS",
                   command=self.import_system_dns).pack(side="left", padx=4)
        ttk.Label(box, text="支持 IP#端口 写法，如 8.8.8.8#53",
                  foreground="#777777").grid(row=3, column=0, columnspan=2,
                                             sticky="w", pady=(4, 0))

    def _build_params(self, parent):
        box = ttk.LabelFrame(parent, text="监测参数", padding=6)
        box.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        self.param_vars = {
            "interval_seconds": tk.StringVar(),
            "timeout_seconds": tk.StringVar(),
            "retries": tk.StringVar(),
            "max_workers": tk.StringVar(),
            "query_type": tk.StringVar(),
            "log_dir": tk.StringVar(),
            "log_all": tk.BooleanVar(),
            "max_rows": tk.StringVar(),
            "refresh_ms": tk.StringVar(),
        }
        specs = (
            ("监测间隔(秒)", "interval_seconds", 8),
            ("单次超时(秒)", "timeout_seconds", 8),
            ("超时重试次数", "retries", 8),
            ("并发线程数", "max_workers", 8),
            ("查询类型", "query_type", 8),
            ("日志目录", "log_dir", 24),
            ("表格最大行数", "max_rows", 8),
            ("界面刷新(毫秒)", "refresh_ms", 8),
        )

        for index, (title, key, width) in enumerate(specs):
            row, column = divmod(index, 4)
            cell = ttk.Frame(box)
            cell.grid(row=row, column=column, sticky="w", padx=(0, 16),
                      pady=3)
            ttk.Label(cell, text=title).pack(anchor="w")
            if key == "query_type":
                combo = ttk.Combobox(cell, textvariable=self.param_vars[key],
                                     values=("A", "AAAA"), width=width - 2,
                                     state="readonly")
                combo.pack(anchor="w")
            else:
                ttk.Entry(cell, textvariable=self.param_vars[key],
                          width=width).pack(anchor="w")

        ttk.Checkbutton(box, text="记录全量日志（关闭则仅记录异常）",
                        variable=self.param_vars["log_all"]).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(box,
                  text="提示：并发数会自动提升到不低于 域名数×服务器数，"
                       "避免超时重试排队阻塞",
                  foreground="#777777").grid(row=2, column=2, columnspan=2,
                                             sticky="w", pady=(4, 0))

    def _build_actions(self, parent):
        bar = ttk.Frame(parent)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(bar, text="保存配置", command=self.save).pack(side="left")
        ttk.Button(bar, text="重新载入", command=self.reload).pack(
            side="left", padx=4)
        ttk.Button(bar, text="应用并重启监测",
                   command=self.apply_and_restart).pack(side="left")
        self.hint = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.hint,
                  foreground="#0a6b0a").pack(side="left", padx=12)

    # ------------------------------------------------ 域名操作

    def add_domain(self):
        self._domain_dialog(None)

    def edit_domain(self):
        selection = self.domain_tree.selection()
        if not selection:
            messagebox.showinfo("编辑域名", "请先选中一行。")
            return
        self._domain_dialog(selection[0])

    def _domain_dialog(self, item):
        current = {"name": "", "expected": "", "enabled": True,
                   "change": True}
        if item is not None:
            values = self.domain_tree.item(item, "values")
            current = {"enabled": values[0] == "是", "name": values[1],
                       "expected": values[2], "change": values[3] == "是"}

        dialog = tk.Toplevel(self.app.root)
        dialog.title("域名配置")
        dialog.transient(self.app.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        body = ttk.Frame(dialog, padding=12)
        body.pack(fill="both", expand=True)

        name_var = tk.StringVar(value=current["name"])
        expected_var = tk.StringVar(value=current["expected"])
        enabled_var = tk.BooleanVar(value=current["enabled"])
        change_var = tk.BooleanVar(value=current["change"])

        ttk.Label(body, text="域名").grid(row=0, column=0, sticky="w",
                                          pady=3)
        name_entry = ttk.Entry(body, textvariable=name_var, width=36)
        name_entry.grid(row=0, column=1, sticky="ew", pady=3)

        ttk.Label(body, text="期望IP").grid(row=1, column=0, sticky="w",
                                            pady=3)
        ttk.Entry(body, textvariable=expected_var, width=36).grid(
            row=1, column=1, sticky="ew", pady=3)
        ttk.Label(body, text="多个 IP 用逗号分隔；留空表示不校验",
                  foreground="#777777").grid(row=2, column=1, sticky="w")

        ttk.Checkbutton(body, text="启用监测", variable=enabled_var).grid(
            row=3, column=1, sticky="w", pady=(6, 0))
        ttk.Checkbutton(body, text="结果变化时提示", variable=change_var).grid(
            row=4, column=1, sticky="w")

        error_var = tk.StringVar(value="")
        ttk.Label(body, textvariable=error_var,
                  foreground=COLOR_ERROR_TEXT).grid(row=5, column=0,
                                                    columnspan=2, sticky="w",
                                                    pady=(6, 0))

        def on_ok():
            name = name_var.get().strip().rstrip(".")
            if not config_mod.is_valid_domain(name):
                error_var.set("域名格式不正确（需至少两级，如 example.com）")
                return
            raw = expected_var.get().strip()
            ips = [p.strip() for p in raw.replace(";", ",").split(",")
                   if p.strip()]
            bad = [ip for ip in ips if not config_mod.is_valid_ip(ip)]
            if bad:
                error_var.set("以下 IP 不合法：%s" % ", ".join(bad))
                return

            values = ("是" if enabled_var.get() else "否", name,
                      ", ".join(ips), "是" if change_var.get() else "否")
            if item is None:
                self.domain_tree.insert("", "end", values=values)
            else:
                self.domain_tree.item(item, values=values)
            dialog.destroy()

        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="确定", command=on_ok).pack(side="right")
        ttk.Button(buttons, text="取消",
                   command=dialog.destroy).pack(side="right", padx=6)

        body.columnconfigure(1, weight=1)
        name_entry.focus_set()
        dialog.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def remove_domain(self):
        selection = self.domain_tree.selection()
        if not selection:
            return
        for item in selection:
            self.domain_tree.delete(item)

    def toggle_domain(self):
        selection = self.domain_tree.selection()
        if not selection:
            return
        for item in selection:
            values = list(self.domain_tree.item(item, "values"))
            values[0] = "否" if values[0] == "是" else "是"
            self.domain_tree.item(item, values=values)

    # ------------------------------------------------ 服务器操作

    def add_server(self):
        text = self.server_entry.get().strip()
        if not text:
            return
        if not config_mod.is_valid_server(text):
            messagebox.showwarning("DNS 服务器", "地址不合法：%s" % text)
            return
        existing = list(self.server_list.get(0, "end"))
        if text in existing:
            self.hint.set("该服务器已在列表中")
            return
        self.server_list.insert("end", text)
        self.server_entry.delete(0, "end")
        self.hint.set("已添加 %s" % text)

    def remove_server(self):
        selection = list(self.server_list.curselection())
        if not selection:
            return
        for index in reversed(selection):
            self.server_list.delete(index)

    def import_system_dns(self):
        servers = config_mod.detect_system_dns_servers()
        if not servers:
            messagebox.showinfo("导入系统DNS",
                                "未能从注册表读取到 DNS 服务器配置。")
            return
        existing = list(self.server_list.get(0, "end"))
        added = 0
        for server in servers:
            if server not in existing:
                self.server_list.insert("end", server)
                added += 1
        self.hint.set("已导入 %d 个系统 DNS 服务器" % added)

    # ------------------------------------------------ 配置读写

    def load_from(self, conf):
        self.domain_tree.delete(*self.domain_tree.get_children())
        for domain in conf.get("domains", []):
            self.domain_tree.insert("", "end", values=(
                "是" if domain.get("enabled", True) else "否",
                domain.get("name", ""),
                ", ".join(domain.get("expected_ips", [])),
                "是" if domain.get("alert_on_change", True) else "否"))

        self.server_list.delete(0, "end")
        for server in conf.get("dns_servers", []):
            self.server_list.insert("end", server)

        self.param_vars["interval_seconds"].set(
            str(conf.get("interval_seconds", 30)))
        self.param_vars["timeout_seconds"].set(
            str(conf.get("timeout_seconds", 2.0)))
        self.param_vars["retries"].set(str(conf.get("retries", 2)))
        self.param_vars["max_workers"].set(str(conf.get("max_workers", 8)))
        self.param_vars["query_type"].set(conf.get("query_type", "A"))
        self.param_vars["log_dir"].set(conf.get("log_dir", "logs"))
        self.param_vars["log_all"].set(bool(conf.get("log_all", True)))
        ui = conf.get("ui", {})
        self.param_vars["max_rows"].set(str(ui.get("max_rows", 5000)))
        self.param_vars["refresh_ms"].set(str(ui.get("refresh_ms", 150)))

    def collect(self):
        """从界面收集配置（未做校验，交由 normalize_config 规整）。"""
        domains = []
        for item in self.domain_tree.get_children():
            values = self.domain_tree.item(item, "values")
            domains.append({
                "enabled": values[0] == "是",
                "name": values[1],
                "expected_ips": [p.strip() for p in values[2].split(",")
                                 if p.strip()],
                "alert_on_change": values[3] == "是",
            })

        return {
            "interval_seconds": self.param_vars["interval_seconds"].get(),
            "timeout_seconds": self.param_vars["timeout_seconds"].get(),
            "retries": self.param_vars["retries"].get(),
            "max_workers": self.param_vars["max_workers"].get(),
            "query_type": self.param_vars["query_type"].get(),
            "log_dir": self.param_vars["log_dir"].get().strip() or "logs",
            "log_all": bool(self.param_vars["log_all"].get()),
            "dns_servers": list(self.server_list.get(0, "end")),
            "domains": domains,
            "ui": {
                "max_rows": self.param_vars["max_rows"].get(),
                "refresh_ms": self.param_vars["refresh_ms"].get(),
                "font_family": self.app.font_family,
                "font_size": self.app.font_size,
            },
        }

    def save(self):
        conf = self.app.apply_config(self.collect(), restart=False)
        if conf is None:
            return
        self.hint.set("配置已保存到 %s" % config_mod.default_config_path())
        self.load_from(conf)

    def reload(self):
        conf, warning = config_mod.load_config_with_status()
        self.load_from(conf)
        self.hint.set(warning or "已从文件重新载入配置")

    def apply_and_restart(self):
        conf = self.app.apply_config(self.collect(), restart=True)
        if conf is None:
            return
        self.load_from(conf)
        self.hint.set("配置已应用，监测已重启")


class App(object):
    """应用主体：持有配置、引擎、日志与刷新定时器。"""

    def __init__(self, root, conf, warning=""):
        self.root = root
        self.conf = conf
        self.font_family = pick_font_family(
            root, conf.get("ui", {}).get("font_family", ""))
        self.font_size = int(conf.get("ui", {}).get("font_size", 10))
        self.max_rows = int(conf.get("ui", {}).get("max_rows", 5000))
        self.refresh_ms = int(conf.get("ui", {}).get("refresh_ms", 150))

        self.output_queue = queue.Queue(maxsize=20000)
        self.engine = None
        self.logger = None
        self.ui_dropped = 0
        self.last_update = None
        self._running = False

        self._setup_style()
        self._build_window(warning)
        self._start_logger()
        self._schedule_refresh()

    # ------------------------------------------------ 初始化

    def _setup_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
        style.configure(".", font=(self.font_family, self.font_size))
        style.configure("Treeview", rowheight=int(self.font_size * 2.2))

    def _build_window(self, warning):
        self.root.title("DNS 解析状态监控")
        self.root.geometry("1180x720")
        self.root.minsize(900, 560)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self.monitor_tab = MonitorTab(notebook, self)
        self.config_tab = ConfigTab(notebook, self)
        notebook.add(self.monitor_tab.frame, text="  实时监控  ")
        notebook.add(self.config_tab.frame, text="  配置  ")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        if warning:
            self.monitor_tab.status_var.set(warning)

    def _start_logger(self):
        log_dir = config_mod.resolve_log_dir(self.conf.get("log_dir", "logs"))
        self.logger = log_writer.LogWriter(
            log_dir, log_all=self.conf.get("log_all", True))
        self.logger.start()

    # ------------------------------------------------ 刷新循环

    def _schedule_refresh(self):
        self.root.after(self.refresh_ms, self._on_tick)

    def _on_tick(self):
        """批量排空队列并刷新界面 —— 高频下也只是一次批量操作。"""
        try:
            results = []
            while len(results) < MAX_BATCH_PER_TICK:
                try:
                    results.append(self.output_queue.get_nowait())
                except queue.Empty:
                    break

            if results:
                self.monitor_tab.append_results(results)
                if self.logger is not None:
                    for result in results:
                        self.logger.write(result)
                self.last_update = results[-1].timestamp.strftime(
                    "%H:%M:%S")

            if self.engine is not None:
                stats = self.engine.stats()
                self.monitor_tab.update_stats(
                    stats, {"last_update": self.last_update,
                            "ui_dropped": self.ui_dropped})
        except Exception as exc:  # noqa: BLE001 - 刷新异常不能终止界面
            self.monitor_tab.status_var.set("界面刷新异常: %s" % exc)
        finally:
            self._schedule_refresh()

    # ------------------------------------------------ 操作

    def on_start(self):
        if self._running:
            return
        conf = config_mod.normalize_config(self.conf)
        problems = config_mod.validate_config(conf)
        if problems:
            messagebox.showwarning("无法启动", "\n".join(problems))
            return

        self.conf = conf
        self.engine = monitor_engine.MonitorEngine(conf, self.output_queue)
        self.engine.start()
        self._running = True
        self.monitor_tab.set_running(True)
        self.monitor_tab.status_var.set(
            "监测中：%d 个域名 × %d 个服务器，间隔 %s 秒" % (
                len([d for d in conf["domains"] if d.get("enabled", True)]),
                len(conf["dns_servers"]), conf["interval_seconds"]))

    def on_stop(self):
        if not self._running:
            return
        if self.engine is not None:
            self.engine.stop()
        self._running = False
        self.monitor_tab.set_running(False)
        self.monitor_tab.status_var.set("监测已停止")

    def apply_config(self, raw_conf, restart=False):
        """校验并应用配置；失败时提示并返回 None。"""
        conf = config_mod.normalize_config(raw_conf)
        problems = config_mod.validate_config(conf)
        if problems:
            messagebox.showwarning("配置无效", "\n".join(problems))
            return None

        old_log_dir = config_mod.resolve_log_dir(
            self.conf.get("log_dir", "logs"))
        new_log_dir = config_mod.resolve_log_dir(conf.get("log_dir", "logs"))

        self.conf = conf
        self.max_rows = int(conf["ui"]["max_rows"])
        self.refresh_ms = int(conf["ui"]["refresh_ms"])

        # 日志目录或范围变化时重建写线程
        if (new_log_dir != old_log_dir or
                conf.get("log_all") != (self.logger.log_all
                                        if self.logger else None)):
            if self.logger is not None:
                self.logger.stop()
            self.logger = log_writer.LogWriter(
                new_log_dir, log_all=conf.get("log_all", True))
            self.logger.start()

        try:
            config_mod.save_config(conf)
        except OSError as exc:
            messagebox.showerror("保存失败", str(exc))

        if restart and self._running:
            self.on_stop()
            self.on_start()
        elif self._running and self.engine is not None:
            self.engine.update_config(conf)

        return conf

    def clear_counters(self):
        if self.engine is not None:
            self.engine.reset_stats()
        self.ui_dropped = 0
        self.last_update = None

    def open_log_dir(self):
        log_dir = config_mod.resolve_log_dir(self.conf.get("log_dir", "logs"))
        if not os.path.isdir(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError as exc:
                messagebox.showerror("打开日志目录", str(exc))
                return
        try:
            os.startfile(log_dir)
        except (AttributeError, OSError) as exc:
            messagebox.showinfo("日志目录", "%s\n(%s)" % (log_dir, exc))

    def on_close(self):
        if self._running and self.engine is not None:
            self.engine.stop()
        if self.logger is not None:
            self.logger.flush_and_wait(timeout=3.0)
            self.logger.stop()
        self.root.destroy()
