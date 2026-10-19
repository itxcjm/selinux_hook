# T4：针对 4.19 的窄范围 DirtySepolicy 探针版本门槛实验

基于 `sukisu-4.19-build-preflight` 的 t3，单独创建 `sukisu-4.19-probe-t4` 分支。

## 改动范围

- **保留** `selinux_414_compat_path()` 原有条件（kver < 4.15），不改变 `write_op_slot_fallback_allowed()` 与内核 ABI 路由；
- 引入 `dirtysepolicy_probe_compat_path()`，仅允许现有 DirtySepolicy 上下文和 access 探针处理函数在 4.19.x 上运行；
- 不更改原有规则表内容，不修改 SELinux 权限，不关闭 Enforcing；
- 模块/产物版本变更为 `1.1.7-fix-beta-6-suki419-t4`。

## 限制和风险

这是用于 **独立验证旧版本分支条件** 的测试构建，不代表正式安全兼容、也不保证 Spring/Hunter 结果变化。检测工具可能比较多个 SELinux 信息来源，单方面变化可能使通道不一致扩大。

由于此 KPM 需要嵌入 KernelPatch/SukiSU 内核镜像，**务必保留已经确认能够启动的 t3 Boot，并准备 fastboot 恢复手段**；当前仅有源代码与 CI 静态构建检查，没有 4.19.157 K40 真机测试。

建议保留 SELinux Enforcing，并检查 `dmesg | grep -i selinux_hook` 中新增探针命中情况，不能仅以检测应用的界面作为确认标准。
