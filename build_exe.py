# -*- coding: utf-8 -*-
"""PyInstaller 打包脚本：生成单文件 DNSMonitor.exe。

用法：
    python build_exe.py              打包单文件（默认）
    python build_exe.py --onedir     打包为目录（AV 误报时的备选方案）
    python build_exe.py --console    保留控制台窗口（排查启动问题用）

打包前请确保已安装依赖：
    python -m pip install pefile altgraph pywin32-ctypes
"""

import os
import shutil
import subprocess
import sys

APP_NAME = "DNSMonitor"
ENTRY = "main.py"
VERSION = "1.0.0.0"

#: 排除用不到的大体积模块，压缩产物尺寸
EXCLUDES = (
    "numpy", "matplotlib", "PIL", "pandas", "scipy",
    "PyQt5", "PyQt6", "PySide2", "PySide6",
    "test", "unittest", "pydoc_data", "lib2to3",
    "email", "html", "http", "xml", "urllib",
)

HERE = os.path.dirname(os.path.abspath(__file__))


def check_dependencies():
    """打包前自检依赖，缺失时给出明确指引而非中途报错。"""
    missing = []
    for module, package in (("PyInstaller", "pyinstaller"),
                            ("pefile", "pefile"),
                            ("altgraph", "altgraph")):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        print("缺少打包依赖: %s" % ", ".join(missing))
        print("请先执行：")
        print("    python -m pip install %s" % " ".join(missing))
        return False

    if sys.platform == "win32":
        try:
            __import__("win32ctypes")
        except ImportError:
            print("提示：未安装 pywin32-ctypes，版本资源功能可能不可用")
            print("      python -m pip install pywin32-ctypes")

    return True


def write_version_file():
    """生成版本资源文件，降低杀软误报概率。"""
    try:
        from PyInstaller.utils.win32.versioninfo import (
            FixedFileInfo, StringFileInfo, StringStruct, StringTable,
            VarFileInfo, VarStruct, VSVersionInfo)
    except ImportError:
        return None

    parts = tuple(int(p) for p in VERSION.split("."))
    version_file = os.path.join(HERE, "_version_info.txt")
    info = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=parts, prodvers=parts, mask=0x3F, flags=0x0,
            OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([StringTable("080404b0", [
                StringStruct("CompanyName", "DNS Monitor"),
                StringStruct("FileDescription", "DNS 解析状态监控程序"),
                StringStruct("FileVersion", VERSION),
                StringStruct("InternalName", APP_NAME),
                StringStruct("OriginalFilename", APP_NAME + ".exe"),
                StringStruct("ProductName", "DNS 解析状态监控"),
                StringStruct("ProductVersion", VERSION),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0804, 1200])]),
        ])
    # 必须用 str() 序列化 —— PyInstaller 用 eval() 读取该文件，
    # repr() 生成的内容缺少类名限定会反序列化失败
    with open(version_file, "w", encoding="utf-8") as handle:
        handle.write(str(info))
    return version_file


def build(onefile=True, console=False):
    entry_path = os.path.join(HERE, ENTRY)
    if not os.path.isfile(entry_path):
        print("未找到入口文件: %s" % entry_path)
        return 1

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", APP_NAME,
        "--distpath", os.path.join(HERE, "dist"),
        "--workpath", os.path.join(HERE, "build"),
        "--specpath", HERE,
    ]
    args.append("--onefile" if onefile else "--onedir")
    args.append("--console" if console else "--windowed")

    for module in EXCLUDES:
        args.extend(["--exclude-module", module])

    version_file = write_version_file()
    if version_file:
        args.extend(["--version-file", version_file])

    args.append(entry_path)

    print("执行打包：")
    print("  " + " ".join(args))
    print()
    result = subprocess.call(args, cwd=HERE)

    if version_file and os.path.isfile(version_file):
        try:
            os.remove(version_file)
        except OSError:
            pass

    if result != 0:
        print("\n打包失败，返回码 %d" % result)
        return result

    target = os.path.join(HERE, "dist",
                          APP_NAME + ".exe" if onefile else APP_NAME)
    print("\n打包完成：%s" % target)
    print("\n部署提示：")
    print("  1. 把 exe 复制到目标机任意目录（建议非系统盘，如 D:\\DNSMonitor\\）")
    print("  2. 首次运行会在 exe 同目录生成 config.json 与 logs\\")
    print("  3. 若杀软误报，改用 --onedir 方式打包，或为该目录添加排除项")
    return 0


def main():
    if not check_dependencies():
        return 2
    onefile = "--onedir" not in sys.argv
    console = "--console" in sys.argv
    return build(onefile=onefile, console=console)


if __name__ == "__main__":
    sys.exit(main())
