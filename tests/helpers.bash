# Shared helpers for guard.bats. Sourced via `load helpers` in the test file.

GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

# run_guard "<command string>" ["<tool name, default Bash>"]
run_guard() {
  local cmd="$1" tool="${2:-Bash}" json
  json="$(jq -n --arg t "$tool" --arg c "$cmd" \
    '{tool_name:$t, tool_input:{command:$c}, hook_event_name:"PreToolUse"}')"
  run bash "$GUARD" <<<"$json"
}

assert_deny() {
  [ "$status" -eq 0 ] || { echo "expected exit 0, got $status; output: $output"; return 1; }
  echo "$output" | grep -q '"deny"' || { echo "expected a deny decision; output: $output"; return 1; }
}

assert_allow() {
  [ "$status" -eq 0 ] || { echo "expected exit 0, got $status; output: $output"; return 1; }
  [ -z "$output" ] || { echo "expected no output (allow); got: $output"; return 1; }
}
