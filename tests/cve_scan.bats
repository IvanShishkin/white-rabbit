#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/analyze/cve_scan.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
FIX="${BATS_TEST_DIRNAME}/fixtures/cve"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

# The dump mirrors server_snapshot.sh output: os-release lines in `meta`,
# dpkg 4-column (binary, version, SOURCE package, SOURCE version) in `packages`.
# libssl3t64 and openssl share the source package `openssl` — the scanner must
# dedup to SOURCE packages (OSV keys Ubuntu/Debian advisories by source).
setup() {
  TMP="$(mktemp -d)"
  DUMP="$TMP/snapshot.txt"
  { printf '===== WR-SECTION: meta =====\n'
    printf 'hostname: testbox\n'
    printf 'ID=ubuntu\n'
    printf 'VERSION_ID="24.04"\n'
    printf '\n===== WR-SECTION: packages =====\n'
    printf 'pkg_manager: dpkg\n'
    printf 'openssl\t3.0.13-0ubuntu3\topenssl\t3.0.13-0ubuntu3\n'
    printf 'libssl3t64\t3.0.13-0ubuntu3\topenssl\t3.0.13-0ubuntu3\n'
    printf 'nginx-core\t1.24.0-2ubuntu7\tnginx\t1.24.0-2ubuntu7\n'
    printf 'vim\t2:9.1.0016-1ubuntu7\tvim\t2:9.1.0016-1ubuntu7\n'
    printf 'safe-pkg\t1.0\tsafe-pkg\t1.0\n'
    printf '\n===== WR-SECTION: end =====\n'
  } > "$DUMP"
}

teardown() { [ -n "${TMP:-}" ] && rm -rf "$TMP" || true; }

guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "emits the cve section marker and the resolved ecosystem" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-SECTION: cve'
  echo "$output" | grep -q 'ecosystem: Ubuntu:24.04:LTS'
}

@test "a KEV-listed CVE is critical regardless of EPSS/CVSS" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local line
  line="$(echo "$output" | grep '^WR-CVE: nginx ')"
  echo "$line" | grep -q 'CVE-2025-1111'
  echo "$line" | grep -q 'sev=crit'
  echo "$line" | grep -q 'kev=yes'
  echo "$line" | grep -q 'fixed=1.24.0-2ubuntu7.1'
}

@test "EPSS above 0.5 drives high severity for a non-KEV CVE" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local line
  line="$(echo "$output" | grep '^WR-CVE: openssl .*CVE-2025-2222')"
  echo "$line" | grep -q 'sev=high'
  echo "$line" | grep -q 'epss=0.91'
  echo "$line" | grep -q 'kev=no'
  echo "$line" | grep -q 'fixed=3.0.13-0ubuntu3.5'
}

@test "low-EPSS non-KEV CVE lands at low severity" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local line
  line="$(echo "$output" | grep '^WR-CVE: vim ')"
  echo "$line" | grep -q 'CVE-2025-4444'
  echo "$line" | grep -q 'sev=low'
  echo "$line" | grep -q 'epss=0.01'
}

@test "a USN advisory id is reported by its CVE alias" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'CVE-2025-4444'
  ! echo "$output" | grep -q '^WR-CVE:.*USN-7777-1'
}

@test "a vulnerability without an available fix is excluded but counted in a note" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '^WR-CVE:.*CVE-2025-3333'
  echo "$output" | grep -qi 'no fixed version'
  echo "$output" | grep -q 'CVE-2025-3333'
}

@test "a clean package produces no fabricated findings" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '^WR-CVE: safe-pkg'
}

@test "findings are sorted critical before high before low" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local crit high low
  crit="$(echo "$output" | grep -n 'sev=crit' | head -1 | cut -d: -f1)"
  high="$(echo "$output" | grep -n 'sev=high' | head -1 | cut -d: -f1)"
  low="$(echo "$output"  | grep -n 'sev=low'  | head -1 | cut -d: -f1)"
  [ -n "$crit" ] && [ -n "$high" ] && [ -n "$low" ]
  [ "$crit" -lt "$high" ]
  [ "$high" -lt "$low" ]
}

@test "a VEX entry suppresses the CVE with its justification" {
  printf 'CVE-2025-4444 vim dev-only editor, host not exposed\n' > "$TMP/vex.txt"
  run env WR_CVE_SOURCE="$FIX" WR_VEX="$TMP/vex.txt" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '^WR-CVE: vim'
  local line
  line="$(echo "$output" | grep '^WR-CVE-SUPPRESSED: vim CVE-2025-4444')"
  echo "$line" | grep -q 'reason=dev-only editor, host not exposed'
}

@test "a VEX wildcard package entry suppresses across packages" {
  printf 'CVE-2025-2222 * accepted until Q3 patch window\n' > "$TMP/vex.txt"
  run env WR_CVE_SOURCE="$FIX" WR_VEX="$TMP/vex.txt" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '^WR-CVE: openssl .*CVE-2025-2222'
  echo "$output" | grep -q '^WR-CVE-SUPPRESSED: openssl CVE-2025-2222'
}

@test "unreachable OSV source degrades to an explicit note, fabricates nothing" {
  mkdir -p "$TMP/empty-source"
  run env WR_CVE_SOURCE="$TMP/empty-source" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qiE 'unreachable|unavailable|invalid'
  ! echo "$output" | grep -q '^WR-CVE:'
}

@test "missing EPSS source degrades to epss=- and OSV-severity fallback" {
  cp -R "$FIX" "$TMP/noepss"
  rm "$TMP/noepss/epss.json"
  run env WR_CVE_SOURCE="$TMP/noepss" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'EPSS.*unavailable'
  # openssl: EPSS unknown, OSV severity High => medium (not silently low, not invented high)
  local line
  line="$(echo "$output" | grep '^WR-CVE: openssl .*CVE-2025-2222')"
  echo "$line" | grep -q 'epss=-'
  echo "$line" | grep -q 'sev=medium'
  # nginx keeps critical: KEV escalation does not depend on EPSS
  echo "$output" | grep '^WR-CVE: nginx ' | grep -q 'sev=crit'
}

@test "missing KEV source degrades to kev=- and EPSS-only ranking" {
  cp -R "$FIX" "$TMP/nokev"
  rm "$TMP/nokev/kev.json"
  run env WR_CVE_SOURCE="$TMP/nokev" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'KEV.*unavailable'
  # nginx: without KEV data its EPSS 0.44 ranks medium — degraded, not invented critical
  local line
  line="$(echo "$output" | grep '^WR-CVE: nginx ')"
  echo "$line" | grep -q 'kev=-'
  echo "$line" | grep -q 'sev=medium'
}

@test "unsupported distro yields an explicit note, no guessing" {
  { printf '===== WR-SECTION: meta =====\nID=gentoo\nVERSION_ID="2.15"\n'
    printf '===== WR-SECTION: packages =====\n'
    printf 'openssl\t3.0.13\topenssl\t3.0.13\n'
    printf '===== WR-SECTION: end =====\n'
  } > "$DUMP"
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'unsupported distro'
  ! echo "$output" | grep -q '^WR-CVE:'
}

@test "debian maps to its major-version ecosystem" {
  { printf '===== WR-SECTION: meta =====\nID=debian\nVERSION_ID="12"\n'
    printf '===== WR-SECTION: packages =====\n'
    printf 'openssl\t3.0.13\topenssl\t3.0.13\n'
    printf '===== WR-SECTION: end =====\n'
  } > "$DUMP"
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'ecosystem: Debian:12'
}

@test "a dump with no packages section yields a note, not a crash" {
  printf '===== WR-SECTION: meta =====\nID=ubuntu\nVERSION_ID="24.04"\n===== WR-SECTION: end =====\n' > "$DUMP"
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'no package inventory'
  ! echo "$output" | grep -q '^WR-CVE:'
}

@test "missing input dump is reported, not crashed" {
  run env WR_CVE_SOURCE="$FIX" bash "$SCRIPT" "/no/such/dump"
  [ "$status" -ne 0 ]
  echo "$output" | grep -qiE 'not readable|missing'
}

@test "the scanner is allowed by its canonical path but NOT by a planted same-named file" {
  [ "$(guard_decision "scripts/analyze/cve_scan.sh reports/snapshot.txt")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/cve_scan.sh a")" = "deny" ]
  [ "$(guard_decision "cve_scan.sh a")" = "deny" ]
  [ "$(guard_decision "./reports/cve_scan.sh a")" = "deny" ]
}

@test "the scanner is read-only by construction (no writes, no mutators in the body)" {
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}
