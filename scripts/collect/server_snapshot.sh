#!/usr/bin/env bash
# White Rabbit — server snapshot collector. STRICTLY READ-ONLY.
# Run remotely without installing anything:
#   ssh user@host 'bash -s' < scripts/collect/server_snapshot.sh
# NOTE: set -e is intentionally NOT used — a missing tool must not abort the
# snapshot; we note it and collect the rest.
set -uo pipefail

WR_COLLECTOR_VERSION=4
SSHD_CONFIG_D="${WR_SSHD_CONFIG_D:-/etc/ssh/sshd_config.d}"
# Filesystem root prefix. Empty in production (reads the real host); a fixture tree
# in tests. Applied to every filesystem read below (never to ssh_config, which has
# its own logic) so the persistence-pack sections are testable without a live host.
R="${WR_ROOT:-}"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Portable file mtime (GNU stat, then BSD/macOS stat). Reads only.
mtime_of() { stat -c '%y' "$1" 2>/dev/null || stat -f '%Sm' "$1" 2>/dev/null || echo '-'; }

# Are we privileged enough to read root-owned files (root, or passwordless sudo)?
# When 0, sections that scan privileged files must NOT emit an affirmative "clean"
# note — a non-root audit can't see other users' 0600 keys/crontabs or /proc/*/exe,
# so an empty result means "not visible", not "absent".
WR_PRIV=0
if [ "$(id -u 2>/dev/null)" = "0" ] || { have sudo && sudo -n true 2>/dev/null; }; then WR_PRIV=1; fi
priv_caveat() { [ "$WR_PRIV" -eq 1 ] || note "$1"; }

# Run a READ-ONLY command, preferring passwordless sudo -n when available (richer/permitted
# output), else the unprivileged form. Used ONLY for reads (sshd -T effective config, firewall
# status, socket owners). NEVER used for mutation. Runs server-side; the local read-only guard
# does not (and need not) see it.
run_ro() {
  if have sudo && sudo -n true 2>/dev/null; then sudo -n "$@" 2>/dev/null && return 0; fi
  "$@" 2>/dev/null
}

# ---- meta ----
section meta
printf 'WR-COLLECTOR-VERSION: %s\n' "$WR_COLLECTOR_VERSION"
if have hostname; then printf 'hostname: '; hostname 2>/dev/null; else note "hostname not present"; fi
if have uname; then printf 'kernel: '; uname -a 2>/dev/null; else note "uname not present"; fi
if have date; then date -u '+collected_utc: %Y-%m-%dT%H:%M:%SZ' 2>/dev/null; fi
if [ -r /etc/os-release ]; then cat /etc/os-release 2>/dev/null; else note "/etc/os-release not readable"; fi

# ---- ssh_config ----
section ssh_config
if have sshd && run_ro sshd -T; then
  note "source=sshd -T (effective config)"
else
  note "sshd -T unavailable (not present or needs root); falling back to config file"
  if [ -r /etc/ssh/sshd_config ]; then
    cat /etc/ssh/sshd_config 2>/dev/null
    if [ -d "$SSHD_CONFIG_D" ]; then
      for f in "$SSHD_CONFIG_D"/*.conf; do
        [ -r "$f" ] || continue
        printf '\n# ---- drop-in: %s ----\n' "$f"
        cat "$f" 2>/dev/null
      done
      note "source=/etc/ssh/sshd_config + ${SSHD_CONFIG_D}/*.conf (files; Match-block overrides NOT resolved)"
    else
      note "source=/etc/ssh/sshd_config (file; Match-block overrides NOT resolved)"
    fi
  else
    note "/etc/ssh/sshd_config not readable"
  fi
fi

# ---- listening ----
section listening
if have ss; then
  run_ro ss -tulpnH || run_ro ss -tulpn || note "ss failed"
elif have netstat; then
  run_ro netstat -tulpn || note "netstat failed"
else
  note "ss and netstat not present"
fi

# ---- firewall ----
section firewall
fw_found=0
if have ufw; then printf 'WR-TOOL: ufw\n'; run_ro ufw status verbose || note "ufw status failed (even with sudo -n)"; fw_found=1; fi
if have iptables; then printf 'WR-TOOL: iptables\n'; run_ro iptables -S || note "iptables -S failed (even with sudo -n)"; run_ro iptables -L -n -v || true; fw_found=1; fi
if have nft; then printf 'WR-TOOL: nft\n'; run_ro nft list ruleset || note "nft list failed (even with sudo -n)"; fw_found=1; fi
[ "$fw_found" -eq 1 ] || note "no firewall tool present (ufw/iptables/nft)"

# ---- users_auth ----
# WHO can log in. UID-0 duplicates (a second root = persistence), empty shadow
# passwords (login with no credential), and accounts carrying a real login shell.
# Shadow hashes are NEVER printed — only the fact that a field is empty.
section users_auth
if [ -r "$R/etc/passwd" ]; then
  awk -F: '$3==0 {print "uid0: "$1}' "$R/etc/passwd" 2>/dev/null
  awk -F: '$7 !~ /(nologin|\/false|\/sync|\/shutdown|\/halt)$/ && $7!="" {print "shell_user: "$1" "$7}' "$R/etc/passwd" 2>/dev/null
else
  note "/etc/passwd not readable"
fi
# Read /etc/shadow ONCE (most sensitive file on the host) — capture, then parse.
if SHADOW="$(run_ro cat "$R/etc/shadow" 2>/dev/null)" && [ -n "$SHADOW" ]; then
  printf '%s\n' "$SHADOW" | awk -F: '$2=="" {print "empty_password: "$1}'
else
  note "/etc/shadow not readable (need root) — empty-password check skipped"
fi
unset SHADOW

# ---- sudoers ----
# Passwordless sudo and membership in privilege groups (docker group == root-equivalent).
section sudoers
sudoers_dump() {
  # sudoers and its drop-ins are 0440 root — read via run_ro, never gate on [ -r ]
  # (that would skip them under a non-root audit even when sudo -n could read them).
  { run_ro cat "$R/etc/sudoers" 2>/dev/null
    for f in "$R"/etc/sudoers.d/*; do [ -e "$f" ] && run_ro cat "$f" 2>/dev/null; done
  } | grep -avE '^[[:space:]]*(#|$)' | grep -aE '[A-Za-z]'
}
SUDO_RULES="$(sudoers_dump)"
if [ -n "$SUDO_RULES" ]; then
  printf '%s\n' "$SUDO_RULES" | grep -aE 'NOPASSWD' | sed 's/^/nopasswd_rule: /' || true
  printf '%s\n' "$SUDO_RULES" | grep -aE '^[^ ]+[[:space:]]+ALL[[:space:]]*=' | sed 's/^/rule: /'
else
  note "no readable sudoers (need root, or none present)"
fi
if [ -r "$R/etc/group" ]; then
  awk -F: '$1 ~ /^(sudo|admin|wheel|docker|root)$/ && $4!="" {print "group: "$1" members="$4}' "$R/etc/group" 2>/dev/null
else
  note "/etc/group not readable"
fi

# ---- authorized_keys ----
# SSH keys are the real access-control list on a key-only host. Inventory per user
# with a count and mtime; a freshly-added key on an otherwise-stable host is a flag.
section authorized_keys
if [ -r "$R/etc/passwd" ]; then
  seen_ak=""            # dedup: two accounts can share a home dir (e.g. root + a UID-0 backdoor)
  unreadable_ak=0
  while IFS=: read -r u home; do
    [ -n "$home" ] || continue
    for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      f="$R$ak"
      # Skip a file path already inventoried under another account sharing this home.
      case " $seen_ak " in *" $f "*) continue;; esac
      # A missing file is genuinely "no keys"; an existing-but-unreadable one is a blind
      # spot under a non-root audit — read via run_ro and note it rather than skip silently.
      # `test -e` returns false BOTH when the file is absent AND when its parent .ssh is
      # unsearchable (0700 owned by another user under a non-root audit) — the latter is a
      # blind spot, not an absence. Only skip when we can actually confirm absence: the .ssh
      # dir must not exist, or must be searchable by us. Otherwise fall through to the run_ro
      # read + UNREADABLE path so a backdoor account's keys are never silently dropped.
      akdir="$(dirname -- "$f")"
      if [ ! -e "$f" ] && { [ ! -e "$akdir" ] || [ -x "$akdir" ]; }; then continue; fi
      content="$(run_ro cat "$f" 2>/dev/null)"
      if [ -z "$content" ] && ! run_ro cat "$f" >/dev/null 2>&1; then
        printf 'authorized_keys: %s %s UNREADABLE (need root)\n' "$u" "$ak"; unreadable_ak=1; continue
      fi
      seen_ak="$seen_ak $f"
      n="$(printf '%s\n' "$content" | grep -avcE '^[[:space:]]*(#|$)')"
      printf 'authorized_keys: %s %s keys=%s mtime=%s\n' "$u" "$ak" "$n" "$(mtime_of "$f")"
      # Print key type + comment ONLY — never the base64 blob. The comment is the trailing
      # field only when it looks like one (contains '@'); a comment-less key has no printable
      # comment, and its last field IS the blob, so we must not print it.
      printf '%s\n' "$content" | grep -avE '^[[:space:]]*(#|$)' \
        | awk '{ t="?"; for(i=1;i<=NF;i++) if($i ~ /^(ssh-|ecdsa-|sk-ssh-|sk-ecdsa-)/){t=$i; break}
                 c=($NF ~ /@/ ? $NF : "(no comment)"); print "  key: " t " " c }'
    done
  done <<EOF
$(awk -F: '{print $1":"$6}' "$R/etc/passwd" 2>/dev/null)
EOF
  [ "$unreadable_ak" -eq 1 ] && priv_caveat "some authorized_keys were unreadable — non-root audit, key inventory incomplete"
else
  note "/etc/passwd not readable — cannot enumerate home dirs"
fi

# ---- scheduled ----
# Cron and systemd timers are the #1 persistence mechanism. Dump system + per-user.
section scheduled
# Drop only whole-line comments/blanks — cron has no inline comments, so a '#' inside a
# command (e.g. a URL fragment) is part of the command and must be preserved verbatim.
for f in "$R/etc/crontab" "$R"/etc/cron.d/*; do
  [ -e "$f" ] || continue
  printf '# ---- %s ----\n' "${f#"$R"}"
  run_ro cat "$f" 2>/dev/null | grep -avE '^[[:space:]]*(#|$)'
done
sched_unreadable=0
for d in "$R/var/spool/cron/crontabs" "$R/var/spool/cron"; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    # Per-user crontabs are 0600 root:crontab — read via run_ro, not plain cat.
    body="$(run_ro cat "$f" 2>/dev/null)"
    if [ -z "$body" ] && ! run_ro cat "$f" >/dev/null 2>&1; then
      printf 'user crontab: %s UNREADABLE (need root)\n' "$(basename -- "$f")"; sched_unreadable=1; continue
    fi
    printf 'user crontab: %s\n' "$(basename -- "$f")"
    printf '%s\n' "$body" | grep -avE '^[[:space:]]*(#|$)'
  done
done
[ "$sched_unreadable" -eq 1 ] && priv_caveat "some user crontabs were unreadable — non-root audit, cron inventory incomplete"
if have systemctl; then
  printf '# ---- systemd timers ----\n'
  # Capture first, THEN head — piping directly into head can SIGPIPE the producer and,
  # under pipefail, fire a spurious "failed" note despite valid output.
  timers="$(run_ro systemctl list-timers --all --no-pager 2>/dev/null)"
  if [ -n "$timers" ]; then printf '%s\n' "$timers" | head -40; else note "systemctl list-timers returned nothing"; fi
else
  note "systemctl not present — timers not enumerated"
fi

# ---- persistence_signals ----
# Classic post-compromise footholds that a config audit misses.
section persistence_signals
if [ -s "$R/etc/ld.so.preload" ]; then
  grep -avE '^[[:space:]]*$' "$R/etc/ld.so.preload" 2>/dev/null | sed 's/^/ld_so_preload: /'
else
  note "ld.so.preload: absent/empty"
fi
deleted_found=0
deleted_blind=0
if [ -d "$R/proc" ]; then
  for e in "$R"/proc/[0-9]*/exe; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    # /proc/PID/exe is readable only by the process owner or root; use run_ro so a
    # privileged audit sees other users' processes.
    tgt="$(run_ro readlink "$e" 2>/dev/null)"
    if [ -z "$tgt" ]; then
      # An empty /proc/PID/exe is EITHER a kernel thread (no executable image — expected even
      # under root, so NOT a blind spot) OR a userspace process whose exe link we lack the
      # privilege to read (a genuine blind spot). /proc/PID/cmdline (world-readable, unlike the
      # ptrace-gated exe link) tells them apart: kernel threads have an EMPTY cmdline, real
      # processes do not. Without this, every host trips a false "scan incomplete" — the kthreads
      # always outnumber the userspace procs — even on a fully-privileged audit.
      cmd="$(run_ro cat "${e%/exe}/cmdline" 2>/dev/null | tr -d '\0')"
      [ -z "$cmd" ] && continue     # kernel thread (or a process that already exited) — expected
      deleted_blind=1; continue     # real process with an opaque exe — a true blind spot
    fi
    case "$tgt" in
      *"(deleted)") printf 'deleted_binary_proc: %s -> %s\n' "${e#"$R"}" "$tgt"; deleted_found=1 ;;
    esac
  done
fi
# Only claim "clean" when every link we tried actually resolved. If any readlink
# failed (the norm under a non-root audit, where other users' /proc/*/exe are opaque),
# an empty result is a blind spot, not an all-clear.
if [ "$deleted_found" -eq 0 ]; then
  if [ "$deleted_blind" -eq 0 ]; then
    note "no deleted-binary processes"
  else
    note "deleted-binary scan incomplete — a process with a real cmdline had an unreadable /proc/*/exe (non-root audit or ptrace-restricted)"
  fi
fi
if [ -r "$R/etc/rc.local" ]; then
  printf '# ---- rc.local ----\n'
  grep -avE '^[[:space:]]*(#|$)' "$R/etc/rc.local" 2>/dev/null | sed 's/^/rc_local: /'
fi
# SUID binaries outside the usual trusted set (light scan, root prefix aware).
# Strip the WR_ROOT prefix with bash parameter expansion, not sed — $R may contain
# regex/delimiter metacharacters that would break a sed s### expression.
for d in "$R/usr/bin" "$R/usr/sbin" "$R/bin" "$R/sbin" "$R/usr/local/bin"; do
  [ -d "$d" ] || continue
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    printf 'suid: %s\n' "${p#"$R"}"
  done <<EOF
$(find "$d" -maxdepth 1 -type f -perm -4000 2>/dev/null)
EOF
done

# ---- patching ----
section patching
if [ -e "$R/var/run/reboot-required" ] || [ -e "$R/run/reboot-required" ]; then
  printf 'reboot_required: yes\n'
  for rr in "$R/var/run/reboot-required.pkgs" "$R/run/reboot-required.pkgs"; do
    [ -r "$rr" ] && { printf 'reboot_required_pkgs:\n'; cat "$rr" 2>/dev/null | head -20; }
  done
else
  printf 'reboot_required: no\n'
fi
if have apt; then
  printf '# ---- apt upgradable ----\n'
  # Capture once (avoids SIGPIPE-under-pipefail spurious failures), report the total, then
  # classify security updates (two-tier: pocket scan, then apt-get -s fallback — see below).
  upg="$(run_ro apt list --upgradable 2>/dev/null | grep -av '^Listing')"
  printf 'upgradable_total: %s\n' "$(printf '%s\n' "$upg" | grep -ac .)"
  # Classify by the POCKET only (the `pkg/pocket1,pocket2 ...` field before the first space),
  # case-insensitively, so `focal-security`, `jammy-security`, Debian's `Debian-Security` and
  # `stable-security` all match while a package literally NAMED *security* (before the `/`) does
  # not. A literal `-security` grep both missed Debian's casing and risked package-name hits.
  sec="$(printf '%s\n' "$upg" | awk -F/ 'NF>1 { p=$2; sub(/ .*/,"",p); if (tolower(p) ~ /security/) print }')"
  sec_src="apt pocket"
  # Prod-run gap (192 upgradable, 0 classified): Ubuntu also delivers security fixes through the
  # -updates pocket, so `apt list --upgradable` shows -updates and the pocket scan finds nothing.
  # `apt-get -s upgrade` (a read-only SIMULATION — no packages are touched) prints the real archive
  # origin on each `Inst` line (e.g. `Ubuntu:22.04/jammy-security`), which we can grep reliably.
  if [ -z "$sec" ] && [ -n "$upg" ] && have apt-get; then
    sim="$(run_ro apt-get -s upgrade 2>/dev/null | grep -a '^Inst')"
    sec="$(printf '%s\n' "$sim" | grep -ai 'security')"
    [ -n "$sec" ] && sec_src="apt-get -s upgrade (archive origin)"
  fi
  if [ -n "$sec" ]; then
    printf 'security_updates: (via %s)\n' "$sec_src"; printf '%s\n' "$sec" | head -80
  else
    note "no security updates classified (none pending, or apt/apt-get could not attribute them)"
  fi
elif have dnf; then
  sec="$(run_ro dnf -q updateinfo list security 2>/dev/null)"
  [ -n "$sec" ] && printf '%s\n' "$sec" | head -80 || note "dnf reported no security updates (or could not query)"
else
  note "no apt/dnf present — pending-update check skipped"
fi
if [ -r "$R/etc/os-release" ]; then
  # Parse (do NOT source) — never execute a file from the audited host.
  os_name="$(grep -aE '^PRETTY_NAME=' "$R/etc/os-release" 2>/dev/null | head -1 | sed -E 's/^PRETTY_NAME=//; s/^"//; s/"$//')"
  printf 'distro: %s\n' "${os_name:-unknown}"
fi

# ---- packages ----
# Full OS package inventory feeding the local CVE matcher (scripts/analyze/cve_scan.sh).
# Four columns: binary package, version, SOURCE package, SOURCE version — the source pair
# matters because Ubuntu/Debian security advisories (and OSV.dev) are keyed by SOURCE
# package, not the binary one. Read-only queries of the local package database.
section packages
if have dpkg-query; then
  printf 'pkg_manager: dpkg\n'
  dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null
elif have rpm; then
  printf 'pkg_manager: rpm\n'
  # rpm has no source/binary split the way dpkg does; emit name+EVR twice so the
  # analyzer sees the same 4-column shape. Epoch only when set.
  rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n' 2>/dev/null
else
  note "no dpkg-query/rpm present — package inventory skipped"
fi

# ---- sysctl_hardening ----
# A small, high-signal set of kernel hardening toggles (not the full CIS list).
section sysctl_hardening
if have sysctl; then
  for k in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict \
           kernel.yama.ptrace_scope net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies \
           net.ipv4.conf.all.accept_redirects net.ipv4.ip_forward \
           net.ipv4.conf.all.accept_source_route fs.protected_hardlinks fs.protected_symlinks; do
    v="$(run_ro sysctl -n "$k" 2>/dev/null)"
    [ -n "$v" ] && printf 'sysctl: %s = %s\n' "$k" "$v" || printf 'sysctl: %s = (unset)\n' "$k"
  done
else
  note "sysctl not present"
fi

# ---- docker ----
# Docker exposure was the real attack surface on the prod VM: published ports bypass
# ufw (DOCKER-USER chain), and docker-group membership / privileged containers == root.
section docker
if have docker; then
  printf '# ---- docker ps ----\n'
  run_ro docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null || note "docker ps failed (daemon down or no permission)"
  printf '# ---- privileged / host-network containers ----\n'
  run_ro docker ps -q 2>/dev/null | while read -r cid; do
    [ -n "$cid" ] || continue
    run_ro docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} netmode={{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null
  done
  note "published ports above BYPASS ufw/INPUT (Docker DNAT via DOCKER-USER) — see knowledge/checks/docker.md"
else
  note "docker not present"
fi

# ---- end ----
section end
note "snapshot complete"
