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


## 六、t2 静态问题定位与只读诊断

t1 已在 K40 上验证可以启动，但春秋仍报 `system_server execmem` 与 `zygote -> adb_data_file search`，Hunter 提示 `CONTEXT_CHANNEL_DISAGREEMENT`。源码分析发现：

1. `dirtysepolicy_access_should_deny()` 中已列出对应上下文对，但其入口由 `kver < 4.15` 限制，所以 4.19 上此路径不会对它们处理；其他 clean policydb 重定向能否工作则取决于初始化、ABI 及实际快照。
2. `fill_clean_status_bytes()` 对 4.19 生成 sequence=0, policyload=0；`patch_response_seqno()` 和 `write_clean_access_seqno_response()` 的一些 access 响应使用 seqno=1，`SELINUX_STATUS_CLEAN_SEQUENCE` 又是 4；不同通道可能产生不一致。
3. `sc_should_deny_full()` 仅在 `sc_full_mode` 时参与过滤；其开启依赖 `g_selinuxfs_layer_alive` 的健康检查，不能假定在 4.19 上会开启。

这些为静态分析依据，不代表 K40 上各个 Hook 的实际执行顺序已确认。

新增两处只读诊断：
- `K40 POLICY PROBE`：记录两组上下文对是否到达 `before_sel_write_access`、查询发起 UID、是否旁路、策略快照是否存在；限制最多输出 24 次。
- `K40 CHANNEL CHECK`：显示固定状态值与 access/policydb 序列号常量。

当前 t2 **没有变更 SELinux 权限判定**，不保证春秋或 Hunter 的检测结果变化。尽量先在现有 t1 上导出日志，而不是立刻再次刷入内核：

```sh
# 内核日志可能包含设备敏感信息，分享前人工检查
su -c 'dmesg | grep -i "\\[selinux_hook\\]" | tail -n 180'
```

还可执行 `tools/audit-k40-policy.sh` 只读汇总模块的 sepolicy.rule 文本与内核日志。找不到文本规则并不意味着没有内核级策略改动。

**禁止为消除检测结果而直接修改核心进程权限或强制冻结 SELinux policyload**；应先排查哪些模块修改了 Policy，并验证设备实际在 Enforcing 下运行。


## 七、剩余两项规则的上游来源与建议排障次序

春秋残留：`system_server process execmem`、`zygote -> adb_data_file dir search`。这些权限在公开模块源码中可核实：

- [NeoZygisk sepolicy.rule](https://github.com/JingMatrix/NeoZygisk/blob/main/module/src/sepolicy.rule)：同时包含上述两项。
- [ReZygisk sepolicy.rule](https://github.com/PerformanC/ReZygisk/blob/main/module/src/sepolicy.rule)：包含 `zygote -> adb_data_file dir search`。
- [Magisk sepolicy/rules.rs](https://github.com/topjohnwu/Magisk/blob/master/native/src/sepolicy/rules.rs)：包含 `system_server process execmem`；不能因此认定 K40 正在运行 Magisk。

这些是**可能来源**，不是对 K40 已安装模块的识别。用户应在手机上确认模块清单，优先使用 `tools/audit-k40-policy.sh`。

建议依次操作：

1. 在不修改内核或 SELinux 的前提下记录模块清单，定位带有上述规则的 `sepolicy.rule` 或启动态脚本。某些框架在二进制内部注入规则，纯文本搜索并不完整。
2. 用模块管理器一次只停用**一个**可疑的 Zygisk 注入桥接模块，重启后核对 LSPosed、应用启动是否正常以及春秋规则是否消失。勿在系统运行时直接删除规则文本，已加载策略不会因此自动恢复。
3. 如果需要判断 Hunter 的通道不一致是否由 `selinux_hook` 造成，应准备一个**同版本内核/SUSFS/SukiSU，但不嵌入本 KPM**的可恢复测试启动镜像，在可回滚条件下对照；不要禁用 SELinux Enforcing。
4. Hunter 的 `Network Trust Local Risk Signal` 与 SELinux 不属于同一类检查。如状态栏显示 VPN，可在安全且获授权的网络环境下关闭 VPN 作一次对照，结合其展开详情确认具体原因；不能假定 VPN 就是风险来源。

### 风险提示

保留 `SELinux Enforcing`，不要为追求检测结果直接添加或移除核心 `system_server` / `zygote` 权限。部分规则可能是注入框架正常运行所必需，必须先找出拥有者及模块依赖。\n
## 八、t4：仅在 4.19.157 试开 DirtySepolicy 查询过滤

用户要求验证在 FolkPatch 曾经正常、SukiSU + SUSFS 下残留两组权限规则的差异。**不要直接把 `selinux_414_compat_path()` 改成 true：** 该函数还被 `write_op_slot_fallback_allowed()` 使用，会改变 4.19 的 Hook 回退逻辑。

本分支 t4 新增 `dirtysepolicy_probe_gate_enabled()`，只在同时满足以下条件时将旧过滤入口放开：

- 构建参数 `K40_TEST_DIRTYSEPOLICY_GATE=1`；
- KPM 获取到的内核版本恰好为 **4.19.157**。

仅替换 `dirtysepolicy_context_should_hide()` 和 `dirtysepolicy_access_should_deny()` 的入口门控，其他旧内核兼容路径不变。启动日志增加 `K40 test gate dirtysepolicy=1 legacy_abi=0`（符合当前内核时的预期）。

**该实验会改变非特权调用者的 SELinux 查询结果，不会删除现有授权。** Hunter 的多通道不一致提示可能依旧存在甚至增加，因此它只能用来验证内核版本门控是否造成了剩余差异，不能证明 SELinux 策略干净。手机未实机验证前，保持 t3 启动镜像可恢复；不要直接覆盖唯一可启动的 Boot。

如需关闭测试开关，在 Makefile 中改为 `-DK40_TEST_DIRTYSEPOLICY_GATE=0` 并重新构建，或继续使用 t3 对应的旧提交。
