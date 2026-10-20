# K40 T11 — file-role context matching A/B test

Baseline: T10 `050cbe7009f95930681e8ac8ae50717d67cdddf1`. This branch changes only three exact context tokens inside
`dirtysepolicy_context_should_hide()`, plus the version string.

The dedicated app_zygote probe shown by the user tested:
- `u:r:ksu_file:s0`
- `u:r:magisk_file:s0`
- `u:r:lsposed_file:s0`

T10 only matched their `u:object_r:...` counterparts. The context predicate is shared
by `/sys/fs/selinux/context`, `/sys/fs/selinux/access`, and
`/proc/self/attr/current` filter branches.

No rule is granted or removed from the live policy. SELinux Enforcing stays on. The
T10 access-gate behavior stays unchanged. Changing an intercepted probe result is
not evidence that the live policy or Android device is unmodified; treat this as a
controlled query-behavior experiment, **not** an attestation or security repair.

Compare T10 and T11 with the same detector version, same modules and a reboot
between tests. Preserve a restorable Boot image and verified T10 fallback.
