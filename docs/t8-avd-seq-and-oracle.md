# K40 / SukiSU Ultra (KernelSU version 12845) — SELinux 检测通道一致性核对

## 已有的确定结论

- Android 13 / Linux 4.19.157，`getenforce` = `Enforcing`。
- KPM `clean-policydb` 有效指针不等于该策略一定来自未被 root 框架修改的时刻；必须区分“快照建立成功”与“快照是原厂内容”。
- 设备日志证明原始 `selinuxfs/access` Hook 生效，并且 t6 以 `EINVAL(-22)` 提前中断部分结构化 AVD 请求。这种行为可导致 Hunter `ACCESS_UNAVAILABLE`。
- t7 允许这些请求走 clean-policydb 流程，Hunter 的 `ACCESS_UNAVAILABLE` 消失，但 Spring 再次看到部分权限授权；该结果表明 **不能仅以两个 Hook 安装成功就认为计算确实用了干净策略**。
- 参考 [DirtySepolicy AppZygote.java](https://github.com/LSPosed/DirtySepolicy/blob/0cda3b89cd168c88cbf639da9e3d4f44d70c0b78/app/src/main/java/org/lsposed/dirtysepolicy/AppZygote.java) 89–118 行，Linux 4.19 对 `status.sequence` 期望为 0，`status.policyload` 期望为 0，而 `avdSeqNo` **独立要求为 1**。此前 t5–t7 把 AVD 序列号绑定到 status.seq=0 是源码错误。

## t8 改动（与 t7 对照）

- 把 AVD 的序列号作为单独常量 `SELINUX_AVD_CLEAN_SEQNO=1`，统一应用于 KPM 返回的 class-0 探针、`context_struct_compute_av` 返回结构及 `sel_write_access` 返回响应。
- `status.sequence` 和 `status.policyload` 仍采用 4.19 所用的 0/0 值。
- **不更改真实授权规则、不关闭 Enforcing，也不宣称 Hunter/春秋已全面通过**。

## 后续需要分开验证的三个问题

1. **哨兵 context 正/负/文件对照**：确保一个不存在的 type 不被误认存在；检查 `/context`、`/access` 及 `/proc/self/attr/current` 是否返回相符的结果。源码中的 `clean_blob_has_name()` 使用二进制子串查找，不能当成真正的 SELinux 上下文合法性验证，因此可能造成假阳性。
2. **策略计算**：t7 的 `g_clean_av_hooked` 与 `g_clean_context_lookup_hooked` 只能证明 Hook 安装成功，不能证明 `sel_write_access` 最终使用了目标 clean-policydb；需要 K40 运行期证据才可判断。
3. **调用通道一致性**：对比原始 syscall、libc 封装与 libselinux，区分 `EPERM`（权限不足）、`EINVAL`（无效输入）、AVD `allowed=0`（策略拒绝）三种不同语义。没有验证前，不能直接把所有错误码合并成一种结果。

## 安全性和版本信息

用户报告 SukiSU / KernelSU 版本为 **12845**，该数值不自动证明内核 KPM SDK、函数签名和 SELinux 注入时序与 FolkPatch 相同。

此次为 t8 独立实验构建（源代码编译后仍需 K40 实机测试），保留 t7 与原可启动 Boot；测试前必须有可恢复的 Boot/Fastboot，保留 SELinux Enforcing。不合并进稳定分支。
