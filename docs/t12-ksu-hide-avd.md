# T12 — 集成上游 KernelSU selinux_hide 的真实 AVD 应答

设备：Redmi K40 (alioth) / Android 13 / Linux 4.19.157 / SukiSU Ultra 12845 / KPM 2819 / SuSFS 1.5.7 (Manual Hook)。
基线：T11 `572c952`。

## 起因：Hunter 的 ACCESS_UNAVAILABLE 是自己造出来的

T11 截图里的两条 `SELinux Policy Check Inconclusive` 完全对称：

```
oracleReasons=[ACCESS_UNAVAILABLE:3, ACCESS_UNAVAILABLE:4 ... ACCESS_UNAVAILABLE:11]
contextEvidence=[]  accessEvidence=[]  otherRiskCodes=[]
```

`contextEvidence` 和 `accessEvidence` 都为空，说明 oracle **一次都没拿到可解析的 SELinux 应答**。
对照 T8 文档的记录，根因是本 KPM 自己的行为：对已知探针直接 `a->ret = -EINVAL`。

`/sys/fs/selinux/access` 的 write handler 收到 `scon tcon class` 后，正常路径是返回一行
`allowed perms auditallow auditdeny seqno flags`。本 KPM 在命中 DirtySepolicy 探针时
提前 `skip_origin = 1` 并返回 `-EINVAL`，oracle 拿到的不是"拒绝"，而是"无法解析"，
于是记为 `ACCESS_UNAVAILABLE`。**这不是策略问题，是应答格式问题。**

## 上游是怎么做的

tiann/KernelSU `kernel/feature/selinux_hide.c` 的 `my_write_access()`（约 133-188 行）：

```c
static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (likely(current_uid().val < 10000)) {
        return orig_access_write(file, buf, size);
    }
    ...
    length = security_context_to_sid_with_policy(backup_sepolicy, scon, sconlen, &ssid, ...);
    length = security_context_to_sid_with_policy(backup_sepolicy, tcon, tconlen, &tsid, ...);
    security_compute_av_user_with_policy(backup_sepolicy, ssid, tsid, tclass, &avd);
    // stock reads 1; a loader load_policy may have bumped the backup before we load
    avd.seqno = 1;
    length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x",
                       avd.allowed, 0xffffffff, avd.auditallow,
                       avd.auditdeny, avd.seqno, avd.flags);
    ...
}
```

要点：**对 app uid 从不返回 `-EINVAL`**。用 backup（干净）策略算完，再逐字节复刻内核格式。
`seqno` 固定 1，因为 stock 开机读到 1，而 `load_policy` 可能已把 backup 的 `latest_granting` 抬高。

## T12 的改动

新增一条自带计算的 AVD 路径，不依赖内核 hook 重定向：

- `hide_sym_value_by_name()` —— name→value 反查。4.19 的
  `policydb_index()` 把 `sym_val_to_name[i]` 分配为 `char *` 数组，索引 `value-1`，
  因此线性扫描比较字符串即可。带 64 槽缓存，`g_clean_policydb` 指针一变就
  `hide_sym_cache_reset()`。
- `hide_parse_context()` —— 解析 `user:role:type[:level]`；type 是 attribute 时判无效，
  与上游 `string_to_context_struct()` 一致。
- `hide_compute_avd()` —— 在 clean policydb 上跑本模块已有的
  `context_struct_compute_av_intel()`，含 `permissive_map`（置 `AVD_FLAGS_PERMISSIVE`）
  与 `allow_unknown`（class==0 时放行 `0xffffffff`）语义；`seqno` 固定
  `SELINUX_AVD_CLEAN_SEQNO`（=1，与 `status.seq` 相互独立）。
- `hide_format_avd()` —— 逐字节复刻 `"%x %x %x %x %u %x"`。KPM 无 libc，手写 hex/dec。
- `k40_hide_avd_ready()` —— 该路径**自带**计算，因此不受 T10 的
  `K40_T10_T4_ACCESS_GATE` 和 `g_clean_av_hooked` / `g_clean_context_lookup_hooked`
  两个重定向 hook 影响，只要 clean policydb 在位且 `flex_array_get` 可用即可。
- 入口接在 `before_sel_write_access()` 中，原 EINVAL 分支**之前**。

### 回退边界

`hide_compute_avd()` 返回 false（未知 type / 未知 class / policydb 不可用）时，
计数 `g_hide_avd_failed` 后**继续落到原有 EINVAL 分支**，行为与 T11 完全一致。
本改动只可能把"以前返回 EINVAL"的查询变成"返回可解析 AVD"，不会引入新的失败模式。

## 安全性边界

- 只读 clean policydb，**不写任何在线策略**，不新增/删除/修改任何规则；
- 不改 SELinux Enforcing，不改 `status` 通道（仍是 4.19 的 seq=0 / pload=0）；
- 不干预 policyload；`uid < 10000` 与策略管理器路径照旧旁路；
- 一次被拦截的查询现在会得到一个**真实决策**。若 clean policydb 本身已被污染，
  这个决策反映的是被污染的快照 —— 这与 T8 文档已记录的风险一致，
  **不构成设备未被修改的证明**。

## 未验证

- **未在 K40 真机验证**：本构建只经过 CI 静态编译预检。
- 未确认 Hunter/春秋的实际结果。`ACCESS_UNAVAILABLE` 消失是可预期的（应答格式已合法），
  但 `oracleTrust` 是否转为 CONFIDENT 取决于 clean policydb 快照本身是否干净。
- `hide_parse_context()` 不解析 MLS range：Android 上 `mls_enabled` 基本为 0，
  level 段只做分隔校验。若目标设备启用了 MLS，需要补 `mls_context_to_sid`。

## 测试步骤

务必先备份可启动 Boot 并准备 fastboot 恢复，SELinux 保持 Enforcing。

```sh
su -c 'getenforce'                      # 应为 Enforcing
su -c 'dmesg | grep -i "KSU HIDE"'      # 应看到 KSU HIDE avd 行（含 class/allowed/seqno）
su -c 'dmesg | grep -i "DIRTYSEPOLICY deny /sys/fs/selinux/access"'  # 应显著减少
```

诊断要点：

- 出现 `KSU HIDE avd` → 新路径生效，`/access` 已返回真实 AVD；
- 完全没有 `KSU HIDE avd` → `k40_hide_avd_ready()` 为 false，检查
  `clean policydb` 是否在位、`flex_array_get` 是否解析成功；
- 只有 `K40 ORACLE TRACE ... intercepted with EINVAL` 而无 `KSU HIDE avd`
  → clean policydb 上算不出，需看 `g_hide_avd_failed` 与 context 合法性。

对比时请固定 Hunter 版本、模块清单一致，并在两次测试之间重启。
保留 T11 作为已验证的回退版本。
