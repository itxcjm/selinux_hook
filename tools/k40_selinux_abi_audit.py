#!/usr/bin/env python3
"""静态核对 4.19 SELinux/KPM 接口；不加载内核模块，不修改策略。"""
from __future__ import annotations
import argparse
import pathlib
import re
import sys

def read_optional(root: pathlib.Path | None, relative: str) -> str | None:
    if root is None:
        return None
    try:
        return (root / relative).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None

def extract_braced_structure(source: str, name: str) -> str:
    # 仅做静态特征检查，不根据源码文本猜测布局偏移。
    mark = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", source)
    if not mark:
        return ""
    start = mark.end()
    depth = 1
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i]
    return ""

def symbol_presence(text: str | None, pattern: str) -> str:
    if text is None:
        return "未提供源文件"
    return "源码中可见" if re.search(pattern, text) else "源码中未找到"

def main() -> int:
    p = argparse.ArgumentParser(description="K40/旧版 SukiSU 的静态 SELinux ABI 差异检查（只读）")
    p.add_argument("--kernel-tree", type=pathlib.Path, help="与设备 Boot 对应的完整内核源码根目录")
    p.add_argument("--kp-tree", type=pathlib.Path, help="用于编译 KPM 的 KernelPatch SDK 目录")
    p.add_argument("--require-kernel", action="store_true", help="没有设备内核源码时返回非零退出码")
    args = p.parse_args()
    security_h = read_optional(args.kernel_tree, "security/selinux/include/security.h")
    selinuxfs = read_optional(args.kernel_tree, "security/selinux/selinuxfs.c")
    hooks = read_optional(args.kernel_tree, "security/selinux/hooks.c")
    services = read_optional(args.kernel_tree, "security/selinux/ss/services.c")
    kpm_h = read_optional(args.kp_tree, "kernel/include/kpmodule.h")
    state = extract_braced_structure(security_h or "", "selinux_state")
    rows = [
        ("selinux_state.ss", symbol_presence(state if security_h is not None else None, r"\*\s*ss\s*;")),
        ("selinux_state.policy", symbol_presence(state if security_h is not None else None, r"\*\s*policy\s*;")),
        ("selinux_state.policy_mutex", symbol_presence(state if security_h is not None else None, r"\bpolicy_mutex\b")),
        ("selinux_state 布局随机化", symbol_presence(security_h, r"__randomize_layout")),
        ("selinuxfs: sel_write_access", symbol_presence(selinuxfs, r"\bsel_write_access\s*\(")),
        ("selinuxfs: sel_write_context", symbol_presence(selinuxfs, r"\bsel_write_context\s*\(")),
        ("hooks: selinux_setprocattr", symbol_presence(hooks, r"\bselinux_setprocattr\s*\(")),
        ("services: context_struct_compute_av", symbol_presence(services, r"\bcontext_struct_compute_av\s*\(")),
        ("KPM SDK: KPM_INIT", symbol_presence(kpm_h, r"#define\s+KPM_INIT\b")),
        ("KPM SDK: KPM_CTL0", symbol_presence(kpm_h, r"#define\s+KPM_CTL0\b")),
        ("KPM SDK: KPM_EXIT", symbol_presence(kpm_h, r"#define\s+KPM_EXIT\b")),
    ]
    print("# SELinux / KPM 静态 ABI 检查")
    print("\n本工具不探测设备，也不执行 Hook。它只能说明提供的源码中有哪些接口。")
    print("\n| 检查项目 | 检查结果 |\n|---|---|")
    for name, result in rows:
        print(f"| {name} | {result} |")
    print("\n注意：‘源码中可见’不等于符号已经导出或运行时调用约定兼容。")
    print("注意：__randomize_layout 存在时严禁据此表猜测 selinux_state 偏移。")
    print("注意：KernelPatch SDK 可以编译 KPM，并不能证明旧版设备 KPM 加载器兼容。")
    if args.require_kernel and security_h is None:
        print("\n错误：没有读取到对应设备的 security.h。", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
