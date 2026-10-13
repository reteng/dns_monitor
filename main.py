# -*- coding: utf-8 -*-
"""DNS 解析状态监控程序入口。

用法：
    python main.py            正常启动图形界面
    pythonw main.py           静默启动（不显示控制台窗口）
"""

import ctypes
import os
import sys
import traceback

import config as config_mod


def enable_dpi_awareness():
    """启用 DPI 感知，避免高分屏下界面模糊。

    Win8.1+ 可用，覆盖目标机 Server 2016；失败时静默降级。
    """
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def install_excepthook(root_getter):
    """把未捕获异常写入日志并提示，避免程序静默退出。"""
    def hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        detail = "".join(traceback.format_exception(
            exc_type, exc_value, exc_tb))
        try:
            log_dir = config_mod.resolve_log_dir("logs")
            if not os.path.isdir(log_dir):
                os.makedirs(log_dir)
            path = os.path.join(log_dir, "dns_monitor_crash.log")
            with open(path, "a", encoding="utf-8") as handle:
                import datetime
                handle.write("\n=== %s ===\n%s" % (
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    detail))
        except Exception:
            path = "(日志写入失败)"

        try:
            from tkinter import messagebox
            messagebox.showerror(
                "程序错误",
                "发生未处理的错误，详情已写入：\n%s\n\n%s" % (
                    path, detail.strip().splitlines()[-1] if detail else ""))
        except Exception:
            sys.stderr.write(detail)

    sys.excepthook = hook


def main():
    enable_dpi_awareness()

    import tkinter as tk
    import gui

    conf, warning = config_mod.load_config_with_status()

    root = tk.Tk()
    try:
        app = gui.App(root, conf, warning)
    except Exception:
        root.destroy()
        raise

    install_excepthook(lambda: root)

    # 命令行带 --start 时自动开始监测
    if "--start" in sys.argv:
        root.after(300, app.on_start)

    try:
        root.mainloop()
    finally:
        # 显式退出：tkinter 配合打包程序时偶见进程残留
        try:
            root.destroy()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
