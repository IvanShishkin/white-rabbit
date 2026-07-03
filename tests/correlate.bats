#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/analyze/correlate.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

setup() {
  DUMPDIR="$(mktemp -d)"
  SSH_DUMP="$DUMPDIR/ssh.txt"
  WEB_DUMP="$DUMPDIR/web.txt"
  cat > "$SSH_DUMP" <<'EOF'
===== WR-SECTION: top_failed_sources =====
817 203.0.113.5 -
12 198.51.100.9 host.example
5 192.0.2.77 -
===== WR-SECTION: accepted_logins =====
9 hola 203.0.113.5 publickey
1 hola 10.0.0.2 publickey
===== WR-SECTION: end =====
EOF
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: top_client_ips =====
500 203.0.113.5 90%
30 198.51.100.9 10%
7 8.8.8.8 0%
===== WR-SECTION: top_scanning_sources =====
120 40 198.51.100.9
===== WR-SECTION: sensitive_path_hits =====
3 200 /.env 203.0.113.5
===== WR-SECTION: login_bruteforce =====
50 198.51.100.9 /wp-login.php 50
===== WR-SECTION: end =====
EOF
}

teardown() { [ -n "${DUMPDIR:-}" ] && rm -rf "$DUMPDIR" || true; }

guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "emits the cross_correlation section marker" {
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-SECTION: cross_correlation'
}

@test "an SSH-accepted IP that also hit the web is critical (foothold + activity)" {
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  local line
  line="$(echo "$output" | grep '203.0.113.5')"
  echo "$line" | grep -q 'severity=critical'
  echo "$line" | grep -qE 'ssh=[^ ]*accepted'
  echo "$line" | grep -qE 'web=[^ ]*sensitive'
}

@test "an SSH brute-forcer that also scans/brute-forces the web is high" {
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  local line
  line="$(echo "$output" | grep '198.51.100.9')"
  echo "$line" | grep -q 'severity=high'
  echo "$line" | grep -qE 'ssh=[^ ]*failed'
  echo "$line" | grep -qE 'web=[^ ]*scanner'
  echo "$line" | grep -qE 'web=[^ ]*login-bf'
}

@test "IPs seen on only one surface are NOT correlated" {
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -qE '^WR-CROSS: 192\.0\.2\.77'   # ssh-only
  ! echo "$output" | grep -qE '^WR-CROSS: 10\.0\.0\.2'     # ssh-only (accepted)
  ! echo "$output" | grep -qE '^WR-CROSS: 8\.8\.8\.8'      # web-only
}

@test "no shared IP => explicit note, no fabricated findings" {
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: top_client_ips =====
7 8.8.8.8 0%
===== WR-SECTION: end =====
EOF
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'no IP appears in both'
  ! echo "$output" | grep -q 'WR-CROSS:'
}

@test "missing input files are reported, not crashed" {
  run bash "$SCRIPT" "/no/such/ssh" "/no/such/web"
  [ "$status" -ne 0 ] || echo "$output" | grep -qi 'WR-NOTE'
  echo "$output" | grep -qiE 'not readable|not found|missing'
}

@test "the correlator is allowed by its canonical path but NOT by a planted same-named file" {
  # Guard runs with the repo as cwd (bats' cwd), so the repo-relative path resolves to the
  # canonical correlator and is allowed...
  [ "$(guard_decision "scripts/analyze/correlate.sh reports/ssh.txt reports/web.txt")" = "allow" ]
  # ...but a same-named file anywhere else is denied (basename allowlisting is NOT used).
  [ "$(guard_decision "/tmp/evil/correlate.sh a b")" = "deny" ]
  [ "$(guard_decision "correlate.sh a b")" = "deny" ]
  [ "$(guard_decision "./reports/correlate.sh a b")" = "deny" ]
}

@test "a dotted-quad embedded in an attacker-controlled path does NOT fabricate a correlation" {
  # sensitive_path_hits carries the request PATH; an attacker can put an IP-looking string there.
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: sensitive_path_hits =====
1 200 /.env?next=203.0.113.5 198.51.100.200
===== WR-SECTION: end =====
EOF
  # 203.0.113.5 IS an SSH source, but only appears here inside the PATH, never as a web client IP.
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '203.0.113.5'          # phantom must not be correlated
  echo "$output" | grep -qi 'no IP appears in both' # the real column IP (198.51.100.200) isn't an SSH source
}

@test "an IPv6 actor present on both surfaces is correlated" {
  cat > "$SSH_DUMP" <<'EOF'
===== WR-SECTION: top_failed_sources =====
40 2001:db8::dead -
===== WR-SECTION: accepted_logins =====
3 hola 2001:db8::dead publickey
===== WR-SECTION: end =====
EOF
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: top_client_ips =====
99 2001:db8::dead 70%
===== WR-SECTION: end =====
EOF
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-CROSS: 2001:db8::dead'
  echo "$output" | grep 'WR-CROSS: 2001:db8::dead' | grep -q 'severity=critical'
}

@test "web presence via an attack payload in the URL path correlates as high" {
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: path_payloads =====
4 198.51.100.9 400 /../../etc/passwd
===== WR-SECTION: end =====
EOF
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | grep '198.51.100.9')"
  echo "$line" | grep -qE 'web=[^ ]*payload'
  echo "$line" | grep -q 'severity=high'   # SSH failed + web path payload
}

@test "web presence via a scanner user-agent (not top_scanning_sources) still correlates" {
  cat > "$WEB_DUMP" <<'EOF'
===== WR-SECTION: suspicious_user_agents =====
12 sqlmap/1.7 198.51.100.9
===== WR-SECTION: end =====
EOF
  run bash "$SCRIPT" "$SSH_DUMP" "$WEB_DUMP"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | grep '198.51.100.9')"
  echo "$line" | grep -qE 'web=[^ ]*ua'
  echo "$line" | grep -q 'severity=high'   # SSH failed + web attack-shaped UA
}

@test "the correlator is read-only by construction (no writes, no mutators in the body)" {
  # No file-write redirect: a '>' followed by a real target (not '&' fd-dup, not '/dev/null').
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}
