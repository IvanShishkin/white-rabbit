#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/report/diff_findings.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

setup() { TMP="$(mktemp -d)"; }
teardown() { [ -n "${TMP:-}" ] && rm -rf "$TMP" || true; }

# Write a findings.json with the given `id:severity:title` triples (one per arg).
mk() {
  local out="$1"; shift
  local arr="" first=1 t
  for t in "$@"; do
    local id="${t%%:*}"; local rest="${t#*:}"; local sev="${rest%%:*}"; local title="${rest#*:}"
    [ $first -eq 1 ] || arr="$arr,"; first=0
    arr="$arr$(jq -n --arg id "$id" --arg sev "$sev" --arg ti "$title" \
      '{id:$id,severity:$sev,area:"patching",title:$ti,evidence:[],why:"w",fix:"f",mitre:null,status:"new"}')"
  done
  printf '{"target":"t","host":"h","collected":"2026-07-13","os":"o","posture":{"read_only":true,"hook_enforced":false},"surfaces":{},"summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"findings":[%s]}' "$arr" > "$out"
}

guard_decision() {
  local o
  o="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$o" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "classifies resolved, still-open and new findings by id" {
  mk "$TMP/old.json" "a:critical:EOL release" "b:high:Shared account"
  mk "$TMP/new.json" "b:high:Shared account" "c:medium:Root SSH"
  run bash "$SCRIPT" "$TMP/old.json" "$TMP/new.json"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-DIFF: a RESOLVED'
  echo "$output" | grep -q 'WR-DIFF: b STILL-OPEN'
  echo "$output" | grep -q 'WR-DIFF: c NEW'
}

@test "emits a summary line with the three counts" {
  mk "$TMP/old.json" "a:critical:x" "b:high:y"
  mk "$TMP/new.json" "b:high:y" "c:medium:z"
  run bash "$SCRIPT" "$TMP/old.json" "$TMP/new.json"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-DIFF-SUMMARY: new=1 still_open=1 resolved=1'
}

@test "a still-open finding whose severity changed shows the old severity" {
  mk "$TMP/old.json" "a:high:Root SSH"
  mk "$TMP/new.json" "a:critical:Root SSH"
  run bash "$SCRIPT" "$TMP/old.json" "$TMP/new.json"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | grep 'WR-DIFF: a STILL-OPEN')"
  echo "$line" | grep -q 'sev=critical'
  echo "$line" | grep -q 'was=high'
}

@test "NEW findings are listed before RESOLVED (regressions first)" {
  mk "$TMP/old.json" "a:critical:gone"
  mk "$TMP/new.json" "z:low:appeared"
  run bash "$SCRIPT" "$TMP/old.json" "$TMP/new.json"
  [ "$status" -eq 0 ]
  local n r
  n="$(echo "$output" | grep -n 'z NEW' | cut -d: -f1)"
  r="$(echo "$output" | grep -n 'a RESOLVED' | cut -d: -f1)"
  [ "$n" -lt "$r" ]
}

@test "all-resolved (fully remediated) reports zero open, zero new" {
  mk "$TMP/old.json" "a:critical:x" "b:high:y"
  mk "$TMP/new.json"
  run bash "$SCRIPT" "$TMP/old.json" "$TMP/new.json"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-DIFF-SUMMARY: new=0 still_open=0 resolved=2'
}

@test "accepts bundle directories and resolves findings.json inside each" {
  mkdir -p "$TMP/old" "$TMP/new"
  mk "$TMP/old/findings.json" "a:critical:x"
  mk "$TMP/new/findings.json" "a:critical:x"
  run bash "$SCRIPT" "$TMP/old" "$TMP/new"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-DIFF: a STILL-OPEN'
}

@test "an unreadable input exits 2" {
  mk "$TMP/new.json" "a:low:x"
  run bash "$SCRIPT" "/no/such.json" "$TMP/new.json"
  [ "$status" -eq 2 ]
}

@test "the differ is allowed by its canonical path but not when planted" {
  [ "$(guard_decision "scripts/report/diff_findings.sh reports/a/findings.json reports/b/findings.json")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/diff_findings.sh a b")" = "deny" ]
  [ "$(guard_decision "diff_findings.sh a b")" = "deny" ]
}

@test "the differ is read-only by construction (no writes, no mutators)" {
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}
