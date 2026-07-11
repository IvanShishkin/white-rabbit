#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/report/validate_findings.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
FIX="${BATS_TEST_DIRNAME}/fixtures/report/findings-valid.json"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

setup() { TMP="$(mktemp -d)"; }
teardown() { [ -n "${TMP:-}" ] && rm -rf "$TMP" || true; }

guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "a well-formed findings.json validates" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-VALIDATE: OK (2 findings)'
}

@test "a missing required finding key fails" {
  jq 'del(.findings[0].fix)' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'finding\[0\] missing key: fix'
}

@test "a bad severity enum fails" {
  jq '.findings[0].severity = "showstopper"' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'bad severity: showstopper'
}

@test "a summary count that disagrees with the findings array fails" {
  jq '.summary.critical = 5' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'summary.critical=5 but findings has 1'
}

@test "an unreadable input exits 2, not 0" {
  run bash "$SCRIPT" "/no/such/file.json"
  [ "$status" -eq 2 ]
}

@test "validator is read-only by construction (no writes, no mutators)" {
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}

@test "validator is allowed by its canonical path but not by a planted same-named file" {
  [ "$(guard_decision "scripts/report/validate_findings.sh reports/x/findings.json")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/validate_findings.sh a")" = "deny" ]
  [ "$(guard_decision "validate_findings.sh a")" = "deny" ]
}

@test "findings as a non-array (wrong type) fails, not OK" {
  jq '.findings = "oops"' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'findings is not an array'
}

@test "summary as a non-object (wrong type) fails, not OK" {
  jq '.summary = 5' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'summary is not an object'
}

@test "a duplicate finding id fails" {
  jq '.findings[1].id = .findings[0].id' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'duplicate finding id'
}

@test "a missing required top-level key (posture) fails" {
  jq 'del(.posture)' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'missing top-level key: posture'
}

@test "a finding missing mitre fails" {
  jq 'del(.findings[0].mitre)' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'finding\[0\] missing key: mitre'
}
