#!/system/bin/sh
# K40 / Android 13 / SukiSU Ultra + SUSFS — read-only SELinux audit.
# This script does not change SELinux enforcing mode or module enablement.
# Intended usage: su -c 'sh /sdcard/Download/audit-k40-policy.sh'

echo '=== Device and SELinux ==='
uname -r
getenforce
echo '=== Installed module inventory ==='
MODULES=/data/adb/modules
if [ ! -d "$MODULES" ]; then
    echo 'No /data/adb/modules directory; module inventory unavailable.'
else
    for dir in "$MODULES"/*; do
        [ -d "$dir" ] || continue
        [ -f "$dir/module.prop" ] || continue
        mod_id="$(sed -n 's/^id=//p' "$dir/module.prop" | head -n 1)"
        mod_name="$(sed -n 's/^name=//p' "$dir/module.prop" | head -n 1)"
        mod_ver="$(sed -n 's/^version=//p' "$dir/module.prop" | head -n 1)"
        if [ -f "$dir/disable" ]; then
            mod_state='DISABLED'
        elif [ -f "$dir/remove" ]; then
            mod_state='PENDING_REMOVAL'
        else
            mod_state='ENABLED'
        fi
        printf '%s | %s | %s | %s\n' "$mod_state" "$mod_id" "$mod_name" "$mod_ver"
    done
fi

echo '=== SELinux policy rule references in module scripts ==='
# Exact triggers from detection: system_server process execmem and
# zygote -> adb_data_file dir search. Other potential contributors are listed.
if [ -d "$MODULES" ]; then
    for dir in "$MODULES"/*; do
        [ -d "$dir" ] || continue
        for name in sepolicy.rule post-fs-data.sh service.sh customize.sh; do
            file="$dir/$name"
            [ -f "$file" ] || continue
            # Only inspect plain-text script/rule files. Do not dump binaries.
            lines="$(grep -inE 'system_server|zygote|adb_data_file|execmem|magiskpolicy|supolicy' "$file" 2>/dev/null | head -n 45)"
            if [ -n "$lines" ]; then
                printf '\n-- %s\n%s\n' "$file" "$lines"
            fi
        done
    done
fi

echo '=== SELinux hook logs (last 180) ==='
dmesg 2>&1 | grep -i '\[selinux_hook\]' | tail -n 180
echo '=== Caution ==='
echo 'A rule can also be injected by the Root framework or from a binary.'
echo 'No matching file does NOT mean a rule is absent.'
echo 'An embedded selinux_hook may alter the observed policy; this is a module-origin audit, not a trusted live policy dump.'
echo 'Review module names, paths and process identifiers before sharing.'
