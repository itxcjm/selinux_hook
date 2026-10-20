# Redmi K40 / SukiSU 12845 — SELinux KPM ABI 核对

本分支以 T11（572c952）为基线，仅增加静态兼容性检查，不修改运行中的 SELinux 行为。

## 已知设备参数

- Redmi K40；Android 13；Linux 4.19.157-perf-g92c089fc2d37
- SukiSU Ultra 核心 12845，GKI 1.0；管理器 v3.1.4 (13000)
- KPM 支持版本 2819（管理器显示构建时间 2025-03-31）
- SuSFS 1.5.7 (Manual Hook)；SELinux Enforcing

## 不能直接编译最新版 selinux_hide.c 的原因

1. 上游功能直接依赖 backup_sepolicy、ksu_dup_sepolicy()、ksu_lsm_hook()、ksu_register_feature_handler() 等内核私有接口，旧 KSU 的 KPM 加载器不会自动提供这些接口。
2. 小米 sm8250 的公开 4.19 参考内核中，struct selinux_state 含 ss 指针且结构标记 __randomize_layout；新版代码访问 policy 与 policy_mutex。不能写死结构偏移或直接采用新结构。
3. T11 的 KernelPatch SDK Gitlink 是 0ceeeb968bef86b48af68640af8b135215dc3399，并不等于实机 2819 KPM 加载器的 ABI。
4. 新版 KSU 在添加自己的权限规则前建立 backup_sepolicy；运行期间的 KPM 快照不保证在同一时机取得。

## 静态检查命令

运行所用内核源码应该与手机实际 Boot 匹配；同平台的参考内核只能帮助发现潜在差异。

```sh
# 检查指定内核源码和 KPM SDK，不会加载模块或改变 SELinux
python3 tools/k40_selinux_abi_audit.py --kernel-tree /path/to/device-kernel --kp-tree KernelPatch --require-kernel
```


脚本只验证接口名在源码中出现，不能代替运行时符号解析、原型核对、策略快照完整性测试或 KPM 加载兼容性测试。

当前**不包含**运行时 Hook、任何伪造权限返回或探针过滤逻辑。

上游参考：
- https://github.com/tiann/KernelSU/blob/main/kernel/feature/selinux_hide.c
- https://github.com/tiann/KernelSU/blob/main/kernel/selinux/rules.c
- https://github.com/LineageOS/android_kernel_xiaomi_sm8250/blob/lineage-22.2/security/selinux/include/security.h
