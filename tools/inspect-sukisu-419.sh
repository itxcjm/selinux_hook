#!/system/bin/sh
# 仅收集只读状态，不修改 SELinux、Root、内核和 KPM。
# 输出到终端，避免在共享存储留下含有设备信息的文件。
echo "=== kernel ==="
uname -a
echo "=== SELinux enforcing ==="
getenforce
echo "=== SELinux interfaces (metadata only) ==="
ls -lZ /sys/fs/selinux/status /sys/fs/selinux/policy 2>&1
echo "=== KPM init and hook diagnostics ==="
# 某些 ROM 禁止访问 dmesg。失败并不意味着 KPM 未加载。
dmesg 2>&1 | grep -E '\[selinux_hook\]|KP.*(symbol|kpm|hook)' | tail -n 250
echo "=== Important ==="
echo "请在分享前移除不想公开的进程名、UID、设备路径与日志。"
