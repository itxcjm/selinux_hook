# K40 / SukiSU Ultra / SUSFS — SELinux KPM 兼容性预检

目标系统：Redmi K40 (alioth), Linux 4.19.157, Android 13, SukiSU Ultra + SUSFS。
此分支现在包含对 `selinux_hook.c` 的**早期加载兼容性修复**：识别早期 KPM 事件、在 SELinux 初始化完成后重试 syscall Hook，以及记录 `status` 系列 Hook 的实际安装错误。未修改 SELinux 策略规则匹配和判决值；不能仅凭编译成功认定已经通过检测。

## 一、构建

在 Actions 中选择 **SukiSU KPM ARM64 preflight**，从 `sukisu-4.19-build-preflight` 分支运行。
成功后下载 `sukisu-kpm-arm64-unverified` 构建产物及 `reports/undefined-symbols.txt`。

注意：AArch64 ELF 格式检查通过，仅证明交叉编译成功；不证明 SukiSU KPM 运行时能够解析对应符号、顺利安装 Hook 或维持系统稳定。

## 二、手机只读诊断

将 `tools/inspect-sukisu-419.sh` 复制到手机，在取得授权的 root shell 中运行：

```sh
# 用实际存储位置代替下面的路径
su -c 'sh /sdcard/Download/inspect-sukisu-419.sh'
```

着重检查：
- `init event` 是否为 `pre-kernel-init`
- `SELinux complete_init done`、`SELinux policy committed`
- `deferred install_write_op_hooks` 是否完成
- `cannot find` / `hook ... failed` / `status read hook skipped`
- `CLEAN policydb_read failed` 或 `clean policy snapshot failed`

## 三、源代码中需注意的地方

- `event_is_post_init` 在某些加载事件下可能误判 SELinux 已就绪。
- `sel_mmap_handle_status`、`sel_read_handle_status`、`security_read_policy` 需要在目标内核上验证符号解析和 ABI。
- `dirtysepolicy_context_should_hide` 与 `dirtysepolicy_access_should_deny` 对某些内核版本包含分支判断；不能只改版本宏就假设兼容。
- KPM 现有代码包括冻结/替换 SELinux status 及规则查询行为。**不建议未经内核 ABI 验证就将测试构建嵌入 Boot**，也不要在真实系统中随意拦截 SELinux policyload 更新。

## 四、风险与边界

此分支是可复现的构建/诊断分支，而不是“已经修好春秋检测”的正式兼容版本。
目前未取得设备上的内核日志，也没有在 K40 上完成运行时验证。
在排查前保留可恢复的原始 Boot，设备须维持 SELinux Enforcing。

## 五、已提交的兼容性修改

- **SukiSU embedded 早期事件**：`paging-init`、`pre-kernel-init`、`post-kernel-init`、`pre-init-first-stage` 和 `pre-exec-init` 暂不视为已完成 SELinux 初始化。
- **延迟 SC Hook**：初始化阶段 `/sys/fs/selinux` 尚未挂载导致 `sc_cache_fop()` 失败时，在 `selinux_complete_init` 与 `selinux_policy_commit` 回调后再次尝试；添加幂等保护和文件操作符判空。
- **SELinux status Hook**：检查 `sel_read_handle_status`、`sel_mmap_handle_status`、`selinux_status_update_seqlock`、`selinux_status_update_policyload` 的 `hook_wrap()` 返回值，失败时不再计入已成功安装的 Hook。

未验证：K40 真机符号 ABI、SukiSU KPM 的 `fp_hook_syscalln()` 行为、策略快照是否干净、检测器是否通过。暂不建议嵌入测试构建，需先备份官方 Boot 并准备恢复措施。
