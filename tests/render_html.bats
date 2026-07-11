#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/report/render_html.sh"
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

@test "renders a self-contained HTML document" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qi '<!doctype html>'
  echo "$output" | grep -q '</html>'
  echo "$output" | grep -q '<style>'
}

@test "includes host, finding titles, and severity classes" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'testbox'
  echo "$output" | grep -q 'EOL release'
  echo "$output" | grep -q 'class="finding critical"'
  echo "$output" | grep -q 'class="finding medium"'
}

@test "renders the severity KPI grid from the summary" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'class="kpi c"'
  echo "$output" | grep -q 'class="kpis"'
}

@test "HTML-escapes untrusted finding content (no injection)" {
  jq '.findings[0].title = "<img src=x onerror=alert(1)>"' "$FIX" > "$TMP/x.json"
  run bash "$SCRIPT" "$TMP/x.json"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -qF '<img src=x onerror=alert(1)>'
  echo "$output" | grep -qF '&lt;img src=x'
}

@test "output is fully self-contained (no external URLs)" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -qiE 'https?://'
}

@test "an optional headline is rendered as the thesis when present" {
  jq '.headline = "Everything hinges on one fact."' "$FIX" > "$TMP/h.json"
  run bash "$SCRIPT" "$TMP/h.json"
  [ "$status" -eq 0 ]
  echo "$output" | grep -qF 'Everything hinges on one fact.'
  echo "$output" | grep -q 'class="thesis"'
}

@test "no thesis block when headline is absent" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  ! echo "$output" | grep -q 'class="thesis"'
}

@test "accepts a bundle directory and resolves findings.json inside" {
  mkdir -p "$TMP/bundle"; cp "$FIX" "$TMP/bundle/findings.json"
  run bash "$SCRIPT" "$TMP/bundle"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q '</html>'
}

@test "deterministic: identical output on repeated runs" {
  a="$(bash "$SCRIPT" "$FIX")"
  b="$(bash "$SCRIPT" "$FIX")"
  [ "$a" = "$b" ]
}

@test "unreadable input exits 2" {
  run bash "$SCRIPT" "/no/such/findings.json"
  [ "$status" -eq 2 ]
}

@test "invalid JSON exits 1, does not crash" {
  printf 'not json' > "$TMP/bad.json"
  run bash "$SCRIPT" "$TMP/bad.json"
  [ "$status" -eq 1 ]
}

@test "renderer writes nothing — stdout only (behavioral read-only)" {
  mkdir -p "$TMP/b"; cp "$FIX" "$TMP/b/findings.json"
  before="$(ls "$TMP/b")"
  bash "$SCRIPT" "$TMP/b" >/dev/null
  after="$(ls "$TMP/b")"
  [ "$before" = "$after" ]
}

@test "renderer body contains no mutating commands (static read-only)" {
  # NOTE: the '>' redirect grep used elsewhere is unsuitable here — HTML markup ('><')
  # would false-positive. Read-only is instead proven behaviorally (test above) plus this
  # mutator-token scan.
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}

@test "renderer allowed by canonical path, denied when planted elsewhere" {
  [ "$(guard_decision "scripts/report/render_html.sh reports/x/findings.json")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/render_html.sh a")" = "deny" ]
  [ "$(guard_decision "render_html.sh a")" = "deny" ]
}
