#!/usr/bin/env bats

load helpers

# ---------- denied: filesystem & destructive ----------
@test "denies rm" { run_guard "rm -rf /tmp/x"; assert_deny; }
@test "denies mv" { run_guard "mv a b"; assert_deny; }
@test "denies dd" { run_guard "dd if=/dev/zero of=/dev/sda"; assert_deny; }
@test "denies in-place sed" { run_guard "sed -i s/a/b/ /etc/hosts"; assert_deny; }

# ---------- denied: privilege / packages / services / firewall ----------
@test "denies sudo" { run_guard "sudo cat /etc/shadow"; assert_deny; }
@test "denies apt install" { run_guard "apt install nginx"; assert_deny; }
@test "denies systemctl stop" { run_guard "systemctl stop sshd"; assert_deny; }
@test "denies ufw enable" { run_guard "ufw enable"; assert_deny; }
@test "denies iptables append" { run_guard "iptables -A INPUT -j DROP"; assert_deny; }
@test "denies kill" { run_guard "kill -9 1234"; assert_deny; }
@test "denies crontab remove" { run_guard "crontab -r"; assert_deny; }

# ---------- denied: full-path binary bypasses (C-1/C-2/I-1) ----------
@test "denies full-path rm inside command substitution" { run_guard 'cat $(/bin/rm -rf /)'; assert_deny; }
@test "denies full-path rm as xargs argument" { run_guard "echo /tmp/f | xargs /bin/rm -rf"; assert_deny; }
@test "denies full-path rm as ssh remote command" { run_guard "ssh host /bin/rm -rf /var"; assert_deny; }

# ---------- denied: redirection & unknown binaries ----------
@test "denies file write redirect" { run_guard "echo hi > /tmp/out.txt"; assert_deny; }
@test "denies append redirect" { run_guard "cat a >> b"; assert_deny; }
@test "denies unknown binary (allowlist)" { run_guard "mycustomtool --do-stuff"; assert_deny; }
@test "denies mutation hidden in pipe" { run_guard "ss -tlnp | rm -rf /"; assert_deny; }
@test "denies mutation inside ssh wrapper" { run_guard "ssh host 'rm -rf /var'"; assert_deny; }

# ---------- denied: write/mutation via allowlisted tools (I-NEW-1/M-3) ----------
@test "denies openssl writing a file with -out" { run_guard "openssl enc -aes-256-cbc -in /etc/shadow -out /tmp/exfil"; assert_deny; }
@test "denies ip link set" { run_guard "ip link set eth0 down"; assert_deny; }
@test "denies ip route add" { run_guard "ip route add default via 192.168.1.1"; assert_deny; }

# ---------- denied: command-runner / engine bypasses (C-1 hardening) ----------
@test "denies env running a mutator" { run_guard "env unlink /etc/motd"; assert_deny; }
@test "denies env install" { run_guard "env install -m777 /etc/hostname /tmp/x"; assert_deny; }
@test "denies sed write command" { run_guard "sed -n 'w /tmp/evil' /etc/hostname"; assert_deny; }
@test "denies awk system mutator" {
  # awk 'BEGIN{system("unlink /etc/motd")}' — awk is off the allowlist; any awk invocation is denied
  run_guard "awk 'BEGIN{system(\"unlink /etc/motd\")}'"
  assert_deny
}
@test "denies xargs running a mutator" { run_guard "echo /etc/motd | xargs unlink"; assert_deny; }
@test "denies find -ok exec" {
  run_guard "find /etc -name x -ok unlink {} ;"
  assert_deny
}
@test "denies bare unlink" { run_guard "unlink /etc/motd"; assert_deny; }
@test "denies useradd" { run_guard "useradd attacker"; assert_deny; }
@test "denies hostnamectl set-hostname" { run_guard "hostnamectl set-hostname pwned"; assert_deny; }
@test "denies crontab install from file" { run_guard "crontab /tmp/evil"; assert_deny; }

# ---------- denied: convergence pass — write flags / mutating subcommands ----------
@test "denies crontab install from stdin (dash)" { run_guard "crontab -"; assert_deny; }
@test "denies openssl rand -writerand (file write)" { run_guard "openssl rand -writerand /etc/hostname 16"; assert_deny; }
@test "denies yq in-place edit (yq removed from allowlist)" { run_guard "yq -i '.a=1' /etc/config.yaml"; assert_deny; }
@test "denies sort -o (overwrites a file)" { run_guard "sort -o /etc/hostname /etc/passwd"; assert_deny; }
@test "denies systemctl set-default" { run_guard "systemctl set-default rescue.target"; assert_deny; }
@test "denies systemctl set-environment" { run_guard "systemctl set-environment FOO=bar"; assert_deny; }
@test "denies sysctl key=value write" { run_guard "sysctl vm.swappiness=10"; assert_deny; }
@test "denies iptables long-form --append" { run_guard "iptables --append INPUT -j DROP"; assert_deny; }
@test "denies nft load ruleset from file" { run_guard "nft -f /tmp/rules"; assert_deny; }
@test "denies hostname set" { run_guard "hostname pwned"; assert_deny; }
@test "denies dpkg install" { run_guard "dpkg -i pkg.deb"; assert_deny; }
@test "denies journalctl vacuum" { run_guard "journalctl --vacuum-size=1M"; assert_deny; }
@test "denies journalctl rotate" { run_guard "journalctl --rotate"; assert_deny; }
@test "denies bare sshd (starts daemon)" { run_guard "sshd"; assert_deny; }
@test "denies sshd -D (starts daemon)" { run_guard "sshd -D"; assert_deny; }
@test "denies sshd -p (starts daemon on a port)" { run_guard "sshd -p 2222"; assert_deny; }
@test "denies sshd -f (starts daemon with config)" { run_guard "sshd -f /tmp/c"; assert_deny; }
@test "denies sshd; ls (starts daemon then chains)" { run_guard "sshd; ls"; assert_deny; }
@test "denies systemctl revert" { run_guard "systemctl revert nginx"; assert_deny; }
@test "denies systemctl clean" { run_guard "systemctl clean foo"; assert_deny; }
@test "denies ssh -o ProxyCommand (local exec)" { run_guard "ssh -o ProxyCommand=nc evil 1 host"; assert_deny; }
@test "denies ip netns exec (local command-runner)" { run_guard "ip netns exec myns somebinary"; assert_deny; }
@test "denies ip -batch (executes commands from file)" { run_guard "ip -batch /tmp/f"; assert_deny; }
@test "denies openssl rehash (writes symlinks)" { run_guard "openssl rehash /somedir"; assert_deny; }
@test "denies rpm install" { run_guard "rpm -i pkg.rpm"; assert_deny; }
@test "denies rpm erase" { run_guard "rpm -e bash"; assert_deny; }
@test "denies yum erase" { run_guard "yum erase httpd"; assert_deny; }
@test "denies dnf reinstall" { run_guard "dnf reinstall bash"; assert_deny; }

# ---------- denied: date setting the system clock ----------
@test "denies date -s (set system clock)" { run_guard "date -s 2020-01-01"; assert_deny; }
@test "denies date --set (set system clock)" { run_guard "date --set=2020-01-01"; assert_deny; }
@test "denies date SysV numeric form" { run_guard "date 010100002020"; assert_deny; }

# ---------- allowed: date read-only uses ----------
@test "allows bare date" { run_guard "date"; assert_allow; }
@test "allows date +%s (format)" { run_guard "date +%s"; assert_allow; }
@test "allows date -u (UTC)" { run_guard "date -u"; assert_allow; }
@test "allows date -d yesterday (display)" { run_guard "date -d yesterday"; assert_allow; }
@test "allows date -Iseconds (ISO format)" { run_guard "date -Iseconds"; assert_allow; }
@test "allows date -r /etc/hostname (file mtime)" { run_guard "date -r /etc/hostname"; assert_allow; }

# ---------- allowed: read-only commands ----------
@test "allows ss" { run_guard "ss -tlnp"; assert_allow; }
@test "allows cat config" { run_guard "cat /etc/ssh/sshd_config"; assert_allow; }
@test "allows journalctl piped to grep" { run_guard "journalctl -u ssh --no-pager | grep Failed"; assert_allow; }
@test "allows ss -i (no false -i match)" { run_guard "ss -i"; assert_allow; }
@test "allows find by name (no -delete/-exec)" { run_guard "find /etc -name sshd_config"; assert_allow; }
@test "allows redirect to /dev/null" { run_guard "dpkg -l 2>/dev/null"; assert_allow; }
@test "allows fd dup redirect" { run_guard "grep -R foo /etc 2>&1"; assert_allow; }
@test "allows leading env assignment" { run_guard "LC_ALL=C dpkg -l"; assert_allow; }
@test "allows ssh wrapping a read-only command" { run_guard "ssh host 'ss -tlnp'"; assert_allow; }
@test "allows systemctl status (read subcommand)" { run_guard "systemctl status sshd"; assert_allow; }

# ---------- allowed: read-only uses of allowlisted tools (I-NEW-1/M-3 non-regression) ----------
@test "allows openssl cert read with -noout" { run_guard "openssl x509 -in /etc/ssl/cert.pem -text -noout"; assert_allow; }
@test "allows ip addr show" { run_guard "ip addr show"; assert_allow; }
@test "allows ip route show" { run_guard "ip route show"; assert_allow; }

# ---------- allowed: C-1 non-regression (allowlist shrink must not break common reads) ----------
@test "allows VAR=val prefix without env" { run_guard "LC_ALL=C dpkg -l"; assert_allow; }
@test "allows cut pipeline" { run_guard "cat /etc/passwd | cut -d: -f1"; assert_allow; }
@test "allows sort pipeline" { run_guard "dpkg -l | sort"; assert_allow; }
@test "allows crontab list" { run_guard "crontab -l"; assert_allow; }
@test "allows hostnamectl status" { run_guard "hostnamectl status"; assert_allow; }

# ---------- allowed: convergence pass — reads of write-capable tools must not regress ----------
@test "allows sort -n (no -o)" { run_guard "sort -n /etc/passwd"; assert_allow; }
@test "allows sort -k2 -r (no -o)" { run_guard "sort -k2 -r file"; assert_allow; }
@test "allows dpkg -l | sort (sort terminal, no -o)" { run_guard "dpkg -l | sort"; assert_allow; }
@test "allows grep -o after sort in a pipe (sort -o pattern must not trip)" { run_guard "cat x | sort | grep -o pattern"; assert_allow; }
@test "allows rpm -qa (query)" { run_guard "rpm -qa"; assert_allow; }
@test "allows rpm -qi (query)" { run_guard "rpm -qi bash"; assert_allow; }
@test "allows rpm -ql (query)" { run_guard "rpm -ql bash"; assert_allow; }
@test "allows dpkg -l (list)" { run_guard "dpkg -l"; assert_allow; }
@test "allows dpkg -L (list files)" { run_guard "dpkg -L bash"; assert_allow; }
@test "allows dpkg -s (status)" { run_guard "dpkg -s bash"; assert_allow; }
@test "allows dpkg-query -l" { run_guard "dpkg-query -l"; assert_allow; }
@test "allows sysctl -a (read all)" { run_guard "sysctl -a"; assert_allow; }
@test "allows sysctl key read (no =)" { run_guard "sysctl vm.swappiness"; assert_allow; }
@test "allows sysctl -a piped to grep (no =-write FP)" { run_guard "sysctl -a | grep net.ipv4"; assert_allow; }
@test "allows hostname (bare read)" { run_guard "hostname"; assert_allow; }
@test "allows hostname -f" { run_guard "hostname -f"; assert_allow; }
@test "allows hostname -I" { run_guard "hostname -I"; assert_allow; }
@test "allows sshd -T (dump config)" { run_guard "sshd -T"; assert_allow; }
@test "allows sshd -t (test config)" { run_guard "sshd -t"; assert_allow; }
@test "allows sshd -T -f (dump named config)" { run_guard "sshd -T -f /etc/ssh/sshd_config"; assert_allow; }
@test "allows systemctl is-enabled (read)" { run_guard "systemctl is-enabled ssh"; assert_allow; }
@test "allows ssh host ls (remote read, no -o local-exec)" { run_guard "ssh host ls"; assert_allow; }
@test "allows ip netns list (read)" { run_guard "ip netns list"; assert_allow; }
@test "allows cat of hostname path (no hostname-set FP)" { run_guard "cat /etc/hostname /etc/hosts"; assert_allow; }
@test "allows stat of hostname path (no hostname-set FP)" { run_guard "stat /etc/hostname /etc/hosts"; assert_allow; }
@test "allows journalctl read piped to grep" { run_guard "journalctl -u ssh | grep Failed"; assert_allow; }
@test "allows journalctl --no-pager" { run_guard "journalctl --no-pager"; assert_allow; }
@test "allows iptables -L -n (list)" { run_guard "iptables -L -n"; assert_allow; }
@test "allows nft list ruleset" { run_guard "nft list ruleset"; assert_allow; }
@test "allows systemctl status sshd (sshd as arg, not daemon)" { run_guard "systemctl status sshd"; assert_allow; }
@test "allows systemctl list-units" { run_guard "systemctl list-units"; assert_allow; }

# ---------- extensions: user-managed local allowlist ----------
@test "denies extension binary without local allowlist" { run_guard "example-scanner scan /var/www"; assert_deny; }

# with_local_allowlist <entry> — copy the real policy into BATS_TEST_TMPDIR (auto-cleaned by
# bats even on failure) with <entry> in allowed-commands.local.txt, and point the guard at it.
with_local_allowlist() {
  cp "$WR_POLICY_DIR/allowed-commands.txt" "$WR_POLICY_DIR/denied-patterns.txt" "$BATS_TEST_TMPDIR/"
  echo "$1" > "$BATS_TEST_TMPDIR/allowed-commands.local.txt"
  export WR_POLICY_DIR="$BATS_TEST_TMPDIR"
}

@test "allows extension binary listed in allowed-commands.local.txt" {
  with_local_allowlist example-scanner
  run_guard "example-scanner scan /var/www"
  assert_allow
}

@test "denylist beats the local allowlist" {
  with_local_allowlist rm
  run_guard "rm -rf /tmp/x"
  assert_deny
}

# ---------- extensions: vetted discovery script by exact path ----------
@test "allows vetted extensions list.sh by exact canonical path" {
  run_guard "${BATS_TEST_DIRNAME}/../scripts/extensions/list.sh"
  assert_allow
}

@test "denies a planted list.sh outside the repo" {
  tmpd="$(mktemp -d)"
  touch "$tmpd/list.sh"
  run_guard "$tmpd/list.sh"
  assert_deny
  rm -rf "$tmpd"
}

@test "denies bare list.sh (basename is not allowlisted)" { run_guard "list.sh"; assert_deny; }

# ---------- passthrough & fail-closed ----------
@test "passes through non-Bash tools" { run_guard "anything at all" "Read"; assert_allow; }

@test "fails closed (exit 2) when jq is unavailable" {
  tmpbin="$(mktemp -d)"
  for t in bash cat grep sed awk basename dirname mktemp env; do
    p="$(command -v "$t" || true)"; [ -n "$p" ] && ln -s "$p" "$tmpbin/$t"
  done
  run env -i PATH="$tmpbin" WR_POLICY_DIR="$WR_POLICY_DIR" bash "$GUARD" \
    <<<'{"tool_name":"Bash","tool_input":{"command":"ls"}}'
  [ "$status" -eq 2 ]
  rm -rf "$tmpbin"
}

@test "fails closed (deny) when policy files are missing" {
  run env WR_POLICY_DIR="/nonexistent/policy/dir" bash "$GUARD" \
    <<<'{"tool_name":"Bash","tool_input":{"command":"ls"}}'
  echo "$output" | grep -q '"deny"' || [ "$status" -eq 2 ]
}
