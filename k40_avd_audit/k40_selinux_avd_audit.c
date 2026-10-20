
#include <stdint.h>
#include <stddef.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <ksyms.h>
#include <kputils.h>
#include <log.h>
KPM_NAME("k40_selinux_avd_audit");
KPM_VERSION("0.1.0-k40");
KPM_LICENSE("GPL-2.0");
KPM_AUTHOR("K40 Diagnostics");
KPM_DESCRIPTION("Read-only SELinux access query return observer");

static void *target;
static volatile uint64_t total, positive, einval, errors;
static volatile int active;
static void observe_access(hook_fargs3_t *a, void *userdata) {
    long ret = (long)a->ret;
    (void)userdata;
    __atomic_fetch_add(&total, 1, __ATOMIC_RELAXED);
    if (ret > 0) __atomic_fetch_add(&positive, 1, __ATOMIC_RELAXED);
    else if (ret == -22) __atomic_fetch_add(&einval, 1, __ATOMIC_RELAXED);
    else if (ret < 0) __atomic_fetch_add(&errors, 1, __ATOMIC_RELAXED);
}
static int append_text(char *buf, int pos, int max, const char *text) {
    while (*text && pos < max - 1) buf[pos++] = *text++;
    return pos;
}
static int append_decimal(char *buf, int pos, int max, uint64_t n) {
    char tmp[24]; int size = 0;
    do { tmp[size++] = '0' + n % 10; n /= 10; } while (n && size < 24);
    while (size && pos < max - 1) buf[pos++] = tmp[--size];
    return pos;
}
static int append_field(char *buf, int pos, int max, const char *name, uint64_t n) {
    pos = append_text(buf, pos, max, name);
    pos = append_decimal(buf, pos, max, n);
    return append_text(buf, pos, max, "\n");
}
static long control(const char *args, char *__user out, int len) {
    char buf[192]; int pos = 0;
    (void)args;
    if (!out || len < 1) return -22;
    pos = append_field(buf, pos, sizeof(buf), "installed=", active);
    pos = append_field(buf, pos, sizeof(buf), "calls=", __atomic_load_n(&total, __ATOMIC_RELAXED));
    pos = append_field(buf, pos, sizeof(buf), "positive=", __atomic_load_n(&positive, __ATOMIC_RELAXED));
    pos = append_field(buf, pos, sizeof(buf), "einval=", __atomic_load_n(&einval, __ATOMIC_RELAXED));
    pos = append_field(buf, pos, sizeof(buf), "other_errors=", __atomic_load_n(&errors, __ATOMIC_RELAXED));
    buf[pos] = 0;
    if (len <= pos) return -28;
    return compat_copy_to_user(out, buf, pos + 1) ? -14 : 0;
}
static long initialize(const char *args, const char *event, void *reserved) {
    hook_err_t rc;
    (void)args; (void)event; (void)reserved;
    if (active) return 0;
    target = (void *)kallsyms_lookup_name("sel_write_access");
    if (!target) { logkw("[k40_avd_audit] sel_write_access missing\n"); return -2; }
    rc = hook_wrap(target, 3, NULL, observe_access, NULL);
    if (rc != HOOK_NO_ERR) {
        logke("[k40_avd_audit] hook_wrap failed rc=%u\n", (unsigned)rc);
        target = NULL;
        return -(long)rc;
    }
    active = 1;
    logki("[k40_avd_audit] observational /access hook installed\n");
    return 0;
}
static long cleanup(void *reserved) {
    (void)reserved;
    if (active && target) hook_unwrap(target, NULL, observe_access);
    target = NULL; active = 0;
    return 0;
}
KPM_INIT(initialize);
KPM_CTL0(control);
KPM_EXIT(cleanup);
