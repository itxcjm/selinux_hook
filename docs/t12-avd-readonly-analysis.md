# K40 T12: SELinux AVD 只读分析（未修改 KPM）

基线：T11 `572c952d7e2e4fff907c858aae404051ec64431f`。设备：Redmi K40，Linux 4.19.157，SukiSU Ultra 12845。

本阶段只核对上传的 `k40_t12_avd.log` 与 T11 源码，不提供伪造 AVD 或规避完整性检测的 Hook 逻辑。

## 日志结果

| 类型 | 条数 |
|---|---:|
| `CLEAN /sys/fs/selinux/access` | 51 |
| 正长度返回 | 18 |
| `-EINVAL` (返回 -22) | 33 |
| `DIRTYSEPOLICY deny` | 27 |
| `SC deny` | 52 |
| `K40 CLEAN REDIRECT` | 0 |
| `K40 CLEAN AVD RESULT` | 0 |

27 次 `DIRTYSEPOLICY deny` 分布于 8 组不同的源/目标/class 三元组。
6 次随机生成的 `hunter_selinux_probe_*` 上下文返回 -22，可能是原生正常行为，不应一概当作缺陷。

## 两层拦截原因

- `before_sys_write` 的系统调用过滤可直接返回 `-EINVAL`，使原生 `sel_write_access` 根本得不到请求。
- T11 的 `k40_clean_avd_route_ready()` 在 Linux 4.19 强制关闭；某些三元组又由 `dirtysepolicy_access_should_deny()` 提前返回 `-EINVAL`。
- `clean_policy_context_to_sid()` 仅检查上下文是否存在，写入 `out_sid=0`，不是新版 KSU 的独立 SID 映射过程。

## 对照验证原则

下一步只能用真正的策略计算来评价内核 ABI、SID 转换、AVD 六字段结果和查询一致性。
原始权限拒绝、无效上下文和 KPM 主动拒绝必须分开统计；不能把它们都改成相同的返回值。

**注意：本文件仅为审计记录。该分支尚未生成或验证任何 T12 KPM。**
