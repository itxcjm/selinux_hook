#!/system/bin/sh
# K40 (alioth) / SukiSU Ultra + SUSFS: read-only SELinux policy diagnostics.
# This does not insert rules, remount filesystems, or change enforcing status.

echo '=== kernel ==='
uname -r
echo '=== enforcing ==='
getenforce

echo '=== selinux_hook kernel log (latest 180 lines) ==='
dmesg 2>&1 | grep -i '\[selinux_hook\]' | tail -n 180

echo '=== installed modules with possibly relevant text sepolicy.rule ==='
find /data/adb/modules -type f -name 'sepolicy.rule' 2>/dev/null | while IFS= read -r path; do
    findings="$(grep -inE 'system_server|zygote|adb_data_file|execmem' "$path" 2>/dev/null | head -n 40)"
    if [ -n "$findings" ]; then
        echo "-- $path"
        printf '%s\n' "$findings"
    fi
done

echo '=== notes ==='
echo 'No matched text does not imply clean policy: patches may be kernel-side or binary.'
echo 'Review logs before sharing; they may reveal module names, file paths or app UIDs.'
