#!/usr/bin/env bats

K="${BATS_TEST_DIRNAME}/../knowledge"

@test "severity rubric and all check catalogs exist and are non-empty" {
  for f in severity.md checks/ssh.md checks/firewall.md checks/ports.md \
           checks/access.md checks/persistence.md checks/patching.md \
           checks/sysctl.md checks/docker.md checks/correlation.md checks/cve.md; do
    [ -s "$K/$f" ] || { echo "missing/empty: $f"; return 1; }
  done
}

@test "every severity tag in the check catalogs is a valid level" {
  # Collect every '- **severity:** X' value and ensure X is in the allowed set.
  local bad
  bad="$(grep -rhoE '^- \*\*severity:\*\* [a-z]+' "$K/checks" \
          | sed -E 's/^- \*\*severity:\*\* //' \
          | grep -vE '^(critical|high|medium|low|info)$' || true)"
  [ -z "$bad" ] || { echo "invalid severity level(s): $bad"; return 1; }
}

@test "each check catalog defines at least one check with an id and a fix" {
  local f
  for f in ssh firewall ports access persistence patching sysctl docker correlation cve; do
    grep -qE '^- \*\*id:\*\* ' "$K/checks/$f.md" || { echo "$f.md has no check id"; return 1; }
    grep -qE '^- \*\*fix:\*\* '  "$K/checks/$f.md" || { echo "$f.md has no fix"; return 1; }
  done
}

@test "persistence & access catalogs carry their compromise-critical checks + mitre" {
  grep -qE '^- \*\*id:\*\* persist-ld-preload'   "$K/checks/persistence.md" || { echo "missing ld.so.preload check"; return 1; }
  grep -qE '^- \*\*id:\*\* access-uid0-duplicate' "$K/checks/access.md"     || { echo "missing UID-0 duplicate check"; return 1; }
  grep -qE '^- \*\*mitre:\*\* ' "$K/checks/persistence.md" || { echo "persistence.md missing mitre"; return 1; }
  grep -qE '^- \*\*mitre:\*\* ' "$K/checks/access.md"      || { echo "access.md missing mitre"; return 1; }
}

@test "auth-log catalog exists and carries the breach-critical check + mitre" {
  local f="${BATS_TEST_DIRNAME}/../knowledge/checks/auth-log.md"
  [ -s "$f" ]
  grep -qE '^- \*\*id:\*\* auth-login-after-bruteforce' "$f" || { echo "missing breach-critical check id"; return 1; }
  grep -qE '^- \*\*severity:\*\* critical' "$f" || { echo "breach check must be critical"; return 1; }
  grep -qE '^- \*\*mitre:\*\* '  "$f" || { echo "missing mitre field"; return 1; }
  grep -qE '^- \*\*id:\*\* ' "$f" && grep -qE '^- \*\*fix:\*\* ' "$f"
}

@test "web-log catalog exists and carries the sensitive-file-exposure critical check + mitre" {
  local f="${BATS_TEST_DIRNAME}/../knowledge/checks/web-log.md"
  [ -s "$f" ]
  grep -qE '^- \*\*id:\*\* web-sensitive-file-exposed' "$f" || { echo "missing sensitive-file-exposed check id"; return 1; }
  grep -qE '^- \*\*severity:\*\* critical' "$f" || { echo "sensitive-file-exposed check must be critical"; return 1; }
  grep -qE '^- \*\*mitre:\*\* ' "$f" || { echo "missing mitre field"; return 1; }
  grep -qE '^- \*\*id:\*\* ' "$f" && grep -qE '^- \*\*fix:\*\* ' "$f"
}

@test "cve catalog carries the KEV-critical check, VEX guidance and mitre" {
  local f="${BATS_TEST_DIRNAME}/../knowledge/checks/cve.md"
  [ -s "$f" ]
  grep -qE '^- \*\*id:\*\* cve-kev-known-exploited' "$f" || { echo "missing KEV check id"; return 1; }
  grep -qE '^- \*\*severity:\*\* critical' "$f" || { echo "KEV check must be critical"; return 1; }
  grep -qE '^- \*\*mitre:\*\* ' "$f" || { echo "missing mitre field"; return 1; }
  grep -qi 'VEX' "$f" || { echo "missing VEX guidance"; return 1; }
}
