# K40 4.19.157：t5 KPM 加载失败分析与 t6 修复

## 设备日志证据

设备 bugreport（2026-10-20 01:30）显示 KPM 内核接口可用，SukiSU Ultra 已执行 t5 加载；加载器能够解析出模块名与版本，随后失败：

```text
KP D name: selinux_magisk_access_filter
KP D version: 1.1.7-fix-beta-6-suki419-t5
overflow in relocation type 283 val ffffffab29cd4740
```

该错误在开机约 6.88 秒、管理器手动加载约 42.38 秒和 69.43 秒重复。不是同名模块已存在（`-EEXIST`）、不是 `init()` 返回错误，也不是 Shell 命令问题。KernelPatch 的重定位阶段先于 KPM 初始化，因此 `selinux_hook` 自身的初始化日志并不会出现。

## t4 / t5 二进制实际差异

从 GitHub Actions 构建产物中提取 ELF，执行：

```sh
# 在有 GNU binutils 的电脑上检查 ARM64 ELF 重定位与未解析符号
readelf -rW selinux_hook_*.kpm | grep 'R_AARCH64_CALL26.*memcpy'
readelf -Ws selinux_hook_*.kpm | grep ' memcpy$'
```

t4 没有未解析的 `memcpy`；t5 多出两处 `R_AARCH64_CALL26 memcpy`（text 偏移 `0xf0`、`0x1b0`）且符号为 `UND`。该 relocation 只有约 ±128 MiB 跳转范围，而本机 `memcpy` 解析到远离 KPM 代码段的内核地址，所以失败。

## t6 修复

- 在 `selinux_hook.c` 增加模块内部 `memcpy` 实现，使用 volatile 字节读写防止编译器将实现重新优化成对自身的调用。
- 在 Makefile 中添加 `-fno-tree-loop-distribute-patterns`，降低 GCC 自动生成库函数调用的概率。
- GitHub Actions 新增 `reports/relocations.txt` 和严格检查：外部 `memcpy` 符号未解析则停止发布；明确要求本模块自有 `memcpy` 定义。
- 保留 t5 的 SELinux 序列号实验逻辑；没有修改 SELinux Enforcing 或新增权限。

## 风险与使用

即使通过 t6 的 ELF 静态校验，仍需实机验证其他 KernelPatch 运行时问题。建议 t4 为可回退已验证版本，**不要在正在运行的嵌入式 KPM 上再动态加载同名 KPM**；先确认旧模块已不在本次启动内核中，避免同名冲突。

如果 t6 再次加载失败，导出加载时段的内核日志（过滤 KernelPatch 和 relocation）以确认新错误，不要只依据管理器的“加载失败”弹窗。
