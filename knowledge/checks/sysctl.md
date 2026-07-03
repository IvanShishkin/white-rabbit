# Checks — kernel hardening (`sysctl_hardening` section)

A small, high-signal set of kernel toggles — NOT the full CIS list (that is noise this
tool deliberately skips). Each line is `sysctl: <key> = <value>` or `= (unset)`. These
are defense-in-depth: report them together as ONE low/medium finding rather than one
finding per key, unless a specific value is actively dangerous.

### Weak kernel hardening posture
- **id:** sysctl-hardening-gaps
- **severity:** low (raise to medium if several are off on an internet-facing host)
- **look for:** values weaker than the hardened baseline below:
  - `kernel.randomize_va_space` should be `2` (full ASLR). `0`/`1` = weakened exploit mitigation.
  - `kernel.kptr_restrict` should be `1` or `2` (hide kernel pointers from `/proc`).
  - `kernel.dmesg_restrict` should be `1` (non-root can't read the kernel ring buffer).
  - `kernel.yama.ptrace_scope` should be `1`+ (restrict one process debugging another — limits credential theft from process memory).
  - `net.ipv4.tcp_syncookies` should be `1` (SYN-flood mitigation).
  - `net.ipv4.conf.all.rp_filter` should be `1` (reverse-path filtering — anti-spoofing).
  - `net.ipv4.conf.all.accept_redirects` should be `0` (ignore ICMP redirects — MITM vector).
  - `net.ipv4.conf.all.accept_source_route` should be `0` (drop source-routed packets).
  - `net.ipv4.ip_forward` should be `0` UNLESS the host is a deliberate router/NAT/Docker host (Docker sets this to `1` — expected there, note it rather than flagging).
  - `fs.protected_hardlinks` / `fs.protected_symlinks` should be `1` (block a class of /tmp symlink races).
- **why:** These mitigations blunt whole classes of local privilege-escalation and network attacks. Individually each is minor; a host with several disabled has a measurably softer kernel.
- **fix:** `# set the hardened values in /etc/sysctl.d/99-hardening.conf (e.g. 'kernel.randomize_va_space=2'), then apply: sudo sysctl --system . Leave net.ipv4.ip_forward as-is on a router/Docker host.`
- **note:** `(unset)` usually means the key doesn't exist on this kernel/namespace — not necessarily a problem; don't report unset keys as disabled.
