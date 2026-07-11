#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/analyze/service_eol.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
FIX="${BATS_TEST_DIRNAME}/fixtures/eol"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

setup() { TMP="$(mktemp -d)"; DUMP="$TMP/snapshot.txt"; }
teardown() { [ -n "${TMP:-}" ] && rm -rf "$TMP" || true; }

# Build a snapshot dump with the given 4-column (tab) package lines in its packages section.
make_dump() {
  { printf '===== WR-SECTION: meta =====\nID=ubuntu\nVERSION_ID="18.04"\n'
    printf '\n===== WR-SECTION: packages =====\npkg_manager: dpkg\n'
    printf '%s\n' "$@"
    printf '\n===== WR-SECTION: end =====\n'
  } > "$DUMP"
}

guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "flags an end-of-life service (nginx 1.14) with its cycle, eol date and latest" {
  make_dump "$(printf 'nginx\t1.14.0-0ubuntu1.11\tnginx\t1.14.0-0ubuntu1.11')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | grep '^WR-EOL: nginx ')"
  echo "$line" | grep -q '1.14.0'
  echo "$line" | grep -q 'cycle=1.14'
  echo "$line" | grep -q 'eol=2019-04-23'
  echo "$line" | grep -q 'latest=1.14.2'
  echo "$line" | grep -q 'status=eol'
}

@test "flags an EOL php interpreter (7.2) from a php7.2-fpm package" {
  make_dump "$(printf 'php7.2-fpm\t7.2.24-0ubuntu0.18.04.17\tphp7.2\t7.2.24-0ubuntu0.18.04.17')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep '^WR-EOL: php ' | grep -q 'status=eol'
  echo "$output" | grep '^WR-EOL: php ' | grep -q 'cycle=7.2'
}

@test "a supported-but-behind-latest version is outdated, not eol" {
  make_dump "$(printf 'nginx\t1.31.0-1\tnginx\t1.31.0-1')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | grep '^WR-EOL: nginx ')"
  echo "$line" | grep -q 'status=outdated'
  echo "$line" | grep -q 'latest=1.31.2'
}

@test "a current (== latest, supported) version is reported current" {
  make_dump "$(printf 'nginx\t1.31.2-1\tnginx\t1.31.2-1')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep '^WR-EOL: nginx ' | grep -q 'status=current'
}

@test "a product endoflife.date does not cover degrades to a note, invents nothing" {
  make_dump "$(printf 'apache2\t2.4.29-1ubuntu4.27\tapache2\t2.4.29-1ubuntu4.27')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q '^WR-EOL: apache'
  echo "$output" | grep -qi 'apache.*not version-checked\|no endoflife.*apache\|apache.*unavailable'
}

@test "an unreachable endoflife source degrades to a note and fabricates nothing" {
  mkdir -p "$TMP/empty"
  make_dump "$(printf 'nginx\t1.14.0-0ubuntu1.11\tnginx\t1.14.0-0ubuntu1.11')"
  run env WR_EOL_SOURCE="$TMP/empty" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q 'status=eol'
  echo "$output" | grep -qiE 'unavailable|unreachable|not version-checked'
}

@test "findings are sorted eol before outdated before current" {
  make_dump \
    "$(printf 'nginx\t1.31.2-1\tnginx\t1.31.2-1')" \
    "$(printf 'php7.2-fpm\t7.2.24-0ubuntu0.18.04.17\tphp7.2\t7.2.24-0ubuntu0.18.04.17')"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  local eol cur
  eol="$(echo "$output" | grep -n 'status=eol' | head -1 | cut -d: -f1)"
  cur="$(echo "$output" | grep -n 'status=current' | head -1 | cut -d: -f1)"
  [ -n "$eol" ] && [ -n "$cur" ]
  [ "$eol" -lt "$cur" ]
}

@test "a dump with no packages section yields a note, not a crash" {
  printf '===== WR-SECTION: meta =====\nID=ubuntu\n===== WR-SECTION: end =====\n' > "$DUMP"
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "$DUMP"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi 'no package inventory'
  ! echo "$output" | grep -q '^WR-EOL:'
}

@test "missing input dump is reported, not crashed" {
  run env WR_EOL_SOURCE="$FIX" bash "$SCRIPT" "/no/such/dump"
  [ "$status" -ne 0 ]
  echo "$output" | grep -qiE 'not readable|missing'
}

@test "the scanner is allowed by its canonical path but NOT by a planted same-named file" {
  [ "$(guard_decision "scripts/analyze/service_eol.sh reports/snapshot.txt")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/service_eol.sh a")" = "deny" ]
  [ "$(guard_decision "service_eol.sh a")" = "deny" ]
}

@test "the scanner is read-only by construction (no writes, no mutators in the body)" {
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}
