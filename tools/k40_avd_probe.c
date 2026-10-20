/*
 * K40 native SELinux AVD reference probe.
 * No KPM hooks; no policy or access-result substitution.
 * Build: cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror tools/k40_avd_probe.c -o k40_avd_probe
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_TXN 4096

/* 解析 AVD 六字段；不能将系统调用错误当成“拒绝”。 */
static int decode(const char *s)
{
    unsigned int allowed, decided, aa, ad, seq, flags;
    char extra;
    if (sscanf(s, " %x %x %x %x %u %x %c", &allowed, &decided,
               &aa, &ad, &seq, &flags, &extra) != 6) {
        fprintf(stderr, "INVALID_AVD: %s\n", s);
        return 3;
    }
    printf("allowed=0x%x\ndecided=0x%x\nauditallow=0x%x\n"
           "auditdeny=0x%x\nseqno=%u\nflags=0x%x\n",
           allowed, decided, aa, ad, seq, flags);
    puts("注意: allowed 是权限位掩码，不是单独的允许/拒绝布尔值。");
    return 0;
}

static int token_ok(const char *s)
{
    size_t n;
    if (!s || !(n = strlen(s)) || n > 1023)
        return 0;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)s[i] <= 32 || (unsigned char)s[i] == 127)
            return 0;
    return 1;
}

static int native_access(const char *path, const char *src, const char *dst,
                         const char *class_arg)
{
    char in[MAX_TXN], out[MAX_TXN], *end;
    unsigned long cls;
    int fd, n;
    ssize_t w, r;
    if (!token_ok(src) || !token_ok(dst))
        return fprintf(stderr, "Invalid context token\n"), 2;
    errno = 0;
    cls = strtoul(class_arg, &end, 10);
    if (errno || !*class_arg || *end || cls == 0 || cls > USHRT_MAX)
        return fprintf(stderr, "Class must be decimal 1..65535\n"), 2;
    n = snprintf(in, sizeof(in), "%s %s %lu", src, dst, cls);
    if (n < 0 || (size_t)n >= sizeof(in))
        return fprintf(stderr, "Query too long\n"), 2;

    /* SELinux simple_transaction 必须在同一个 fd 中先写后读。 */
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return fprintf(stderr, "OPEN_FAILED errno=%d %s\n", errno, strerror(errno)), 4;
    w = write(fd, in, (size_t)n);
    if (w != n) {
        fprintf(stderr, "WRITE_FAILED ret=%zd errno=%d %s\n", w, errno, strerror(errno));
        close(fd);
        return 5;
    }
    r = read(fd, out, sizeof(out) - 1);
    if (r < 0) {
        fprintf(stderr, "READ_FAILED errno=%d %s\n", errno, strerror(errno));
        close(fd);
        return 6;
    }
    close(fd);
    out[r] = 0;
    printf("WRITE_LEN=%zd READ_LEN=%zd RAW_AVD=%s\n", w, r, out);
    return decode(out);
}

int main(int argc, char **argv)
{
    const char *path = "/sys/fs/selinux/access";
    int offset = 1;
    if (argc == 3 && !strcmp(argv[1], "--decode"))
        return decode(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "--access")) {
        if (argc < 4)
            goto usage;
        path = argv[2];
        offset = 3;
    }
    if (argc - offset == 3)
        return native_access(path, argv[offset], argv[offset+1], argv[offset+2]);
usage:
    fprintf(stderr, "Usage: %s [--access PATH] SRC_CTX DST_CTX CLASS_ID\n"
                    "       %s --decode 'allowed decided auditallow auditdeny seqno flags'\n",
            argv[0], argv[0]);
    return 2;
}
