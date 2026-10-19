# K40 t5：SELinux 查询通道一致性对照

设备：Redmi K40 (alioth) / Android 13 / kernel 4.19.157 / SukiSU Ultra + SUSFS。

## 起因

用户反馈 t4 之后春秋检测正常；Hunter 6.72 仍出现：
- `status.sequence=0`、`status.policyload=0`、`access.avd.seqno=1`；
- `ACCESS_UNAVAILABLE:3..11` 和 `CONTEXT_CHANNEL_DISAGREEMENT:9,10`；
- 在 `app_zygote` 环境通过 `/proc/self/attr/current` 探测 `ksu_file`、`magisk_file` 时收到 `EPERM`，其他一些上下文得到 `EINVAL`。

`ACCESS_UNAVAILABLE` 不是证明策略干净：它通常表示查询没有成功返回可解析的 AVD，可能来自 KPM 主动以 `-EINVAL` 中断原始 selinuxfs 查询。

## t5 的实际改动

仅对两个已经存在的 AVD 序列号输出通道统一取值来源：
- `after_sel_write_common()` 的 `patch_response_seqno()` 不再直接写死 1，改为采用本 KPM 生成的 `g_clean_status_bytes` 的 `sequence` 字段；
- `write_clean_access_seqno_response()` 对自建的 class=0 AVD 响应也保持一致；
- 在原有直接返回 `-EINVAL` 的 DirtySepolicy access 处理支路添加 **最多 24 次**的 `K40 ORACLE TRACE` 提醒，帮助辨别 `ACCESS_UNAVAILABLE` 来源。
- 使用独立版本 `1.1.7-fix-beta-6-suki419-t5`，并保留 t4 未更改。

**重要：t5 不会解决有效 context 在 app_zygote 下 `EPERM` 的问题，也没有更改返回 `-EINVAL` 的旧规则逻辑。因此 ACCESS_UNAVAILABLE 可能依然存在。**

## 调查建议

1. 保留正在正常工作的 t4 Boot 及可还原的镜像，确认手机能从 fastboot 恢复后才考虑比较 t5；不要直接覆盖没有备份的 Boot。
2. 查看 `su -c 'getenforce'`，应保持 `Enforcing`。
3. 对比 `su -c 'dmesg | grep -E "K40 ORACLE TRACE|K40 POLICY PROBE|hook .*failed"'`（当前日志可能被环形缓冲区覆盖）。
4. Hunter 的 `TrichromeLibrary64.apk` 映射异常属于进程级诊断，不是内核 SELinux 规则问题；可在关闭对应 LSPosed 模块或切换 WebView 提供者时，单项对照，避免同时改动内核与模块。
5. 若需要得到真正可信的安全状态，应针对 Zygisk/Root 组件加载的真实 SELinux 授权进行审计，而非将权限检查失败视为安全。

## 风险

本分支只通过 CI 编译预检，不能证明 K40 实机加载、稳定性、安全性或检测工具结果。修改 status/AVD 输出是用于比较两通道内部一致性的实验，不等价于修复真实 SELinux Policy。
