# t7：4.19 /access 结构化 AVD 应答实验

基线：`sukisu-4.19-reloc-fix-t6`，其代码及 Boot 镜像不更改。

## 来自 K40 设备日志的证据
- `getenforce` = `Enforcing`。
- `g_clean_policydb` 可用，`g_clean_policy_blob` 可用；`STATUS mmap patch seq=0 pload=0` 已运行。
- 系统调用层对部分可疑上下文返回 `EINVAL`；SELinuxfs 的 `DIRTYSEPOLICY deny` 对格式正常的 access 请求也直接返回 `-EINVAL`，与 Hunter `ACCESS_UNAVAILABLE` 表现吻合。
- 其他 access 查询有正常长度的结构化响应（如 `ret=25/29/31`）；Hunter 仍可能报告 context channel mismatch，因为 `/context`、`/proc/self/attr/current`、`/access` 采用不同的判断。
- 用户日志中 `clean_policydb` 非 NULL 只证明有快照，并不保证原始 clean 策略未被其他框架修改，也不能证明 compute AV Hook 实际被调用。

## t7 代码改动
- 新增 `g_clean_av_hooked` 与 `g_clean_context_lookup_hooked`，仅在对应 `hook_wrap` 确认成功后置位。
- 仅在 Linux 4.19、clean policydb 已加载、两个计算/解析 Hook 均安装成功时，对既有 DirtySepolicy 检测上下文不再抢先返回 `-EINVAL`，让 SELinuxfs 查询在 clean-eval scope 下继续走原生权限计算。
- 如果准备条件不满足，保留 t6 早期返回逻辑。该实验不更改所有内核的 SELinux ABI 判断，不直接新增/删减系统授权规则，也不关闭 SELinux Enforcing。
- 试验版本号为 `1.1.7-fix-beta-6-suki419-t7`。

## 风险和未解决部分
- **t7 未经过 K40 真机验证**，编译不保证能正常加载。真实权限计算如发生错误或跨策略 ABI 不匹配，可能影响系统稳定性。
- 这次仅隔离测试 `/access` 查询提前返回 `EINVAL` 的问题，未修改 `/context` 及 `/proc/self/attr/current`，因此 Hunter 的 Context disagreement 不保证消失。
- clean-policydb 可能已含额外授权，恢复结构化返回后春秋的旧告警可能再次出现。这是一份行为对照实验，不能保证所有扫描工具同时通过。

务必保留经过实机验证可启动的 Boot 镜像，并具备 fastboot 恢复办法；暂不合并到稳定分支。手机端先收集新旧版本的 `[selinux_hook]` 日志及返回码，而不只看检测器是否显示“通过”。
