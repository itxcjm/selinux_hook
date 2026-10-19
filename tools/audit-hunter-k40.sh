#!/system/bin/sh
# K40 / SukiSU / Hunter: read-only triage.
# No SELinux mutations, hiding, tracing, policy reloads or process termination.

echo '=== Kernel / SELinux ==='
uname -r
getenforce
echo '=== SELinux interface metadata ==='
ls -lZ /sys/fs/selinux/status /sys/fs/selinux/policy /proc/self/attr/current 2>&1
echo '=== KPM startup and oracle diagnostics (bounded) ==='
dmesg 2>&1 | grep -E '\[selinux_hook\].*(K40 CHANNEL|K40 ORACLE|K40 POLICY|DIRTYSEPOLICY|CLEAN|failed|cannot find|defer)' | tail -n 160
echo '=== Enabled module names only ==='
mods=/data/adb/modules
if [ -d "$mods" ]; then
  for dir in "$mods"/*; do
    [ -d "$dir" ] || continue
    [ -f "$dir/module.prop" ] || continue
    mod_id="$(sed -n 's/^id=//p' "$dir/module.prop" | head -n 1)"
    mod_name="$(sed -n 's/^name=//p' "$dir/module.prop" | head -n 1)"
    if [ -e "$dir/disable" ]; then state=DISABLED; else state=ENABLED; fi
    printf '%s | %s | %s\n' "$state" "$mod_id" "$mod_name"
  done
fi
echo '=== app_zygote / webview process labels ==='
ps -AZ 2>&1 | grep -E 'app_zygote|webview_zygote|webview' | head -n 30
echo '=== Current WebView provider ==='
cmd webviewupdate get-current-webview-package 2>&1
echo '=== WebView provider detail (limited) ==='
dumpsys webviewupdate 2>&1 | head -n 65
echo '=== Trichrome / WebView packages ==='
pm list packages 2>&1 | grep -Ei 'trichrome|webview' | head -n 30
echo '=== Reminder ==='
echo 'Before sharing, review app names and sensitive paths.'
echo 'These results cannot establish a trustworthy clean policy because KPM may intercept SELinux reads.'
