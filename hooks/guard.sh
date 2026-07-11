#!/usr/bin/env bash
set -euo pipefail

# Resolve policy directory: explicit override > plugin root (production) > repo root (script dir).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="${WR_POLICY_DIR:-${CLAUDE_PLUGIN_ROOT:-$(dirname "$SCRIPT_DIR")}/policy}"
ALLOW_FILE="$POLICY_DIR/allowed-commands.txt"
DENY_FILE="$POLICY_DIR/denied-patterns.txt"
# Optional user-managed allowlist for extension binaries (gitignored; the USER maintains it,
# never an extension itself). Absent file = base behavior. Denylist still applies first.
LOCAL_ALLOW_FILE="$POLICY_DIR/allowed-commands.local.txt"

# Canonical paths of White Rabbit's own vetted analysis scripts. These are allowed to run
# LOCALLY (unlike the allowlist, which is basename-based), but ONLY when the invoked path
# resolves to exactly one of these files under the plugin/repo root — never by basename, so a
# same-named script planted in an attacker-controlled cwd/checkout does NOT pass the guard.
WR_ROOT_DIR="$(cd "$(dirname "$POLICY_DIR")" 2>/dev/null && pwd || true)"
WR_CORRELATOR="${WR_ROOT_DIR}/scripts/analyze/correlate.sh"
WR_CVE_SCANNER="${WR_ROOT_DIR}/scripts/analyze/cve_scan.sh"
WR_SERVICE_EOL="${WR_ROOT_DIR}/scripts/analyze/service_eol.sh"
WR_EXT_LIST="${WR_ROOT_DIR}/scripts/extensions/list.sh"
WR_VALIDATE_FINDINGS="${WR_ROOT_DIR}/scripts/report/validate_findings.sh"
WR_RENDER_HTML="${WR_ROOT_DIR}/scripts/report/render_html.sh"

# Fail closed if jq is unavailable: we cannot safely parse input, so block (exit 2).
if ! command -v jq >/dev/null 2>&1; then
  echo "White Rabbit guard: jq not found — failing closed (read-only)." >&2
  exit 2
fi

deny() {
  jq -n --arg r "$1" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}
allow() { exit 0; }

INPUT="$(cat)"

# Unparseable input => fail closed.
if ! TOOL_NAME="$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)"; then
  deny "White Rabbit guard: unparseable hook input — failing closed."
fi

# Only guard Bash; other tools are governed by Claude Code permissions.
case "$TOOL_NAME" in
  Bash|"") : ;;   # guard Bash, and guard empty/unknown-but-parseable as Bash (fail closed)
  *) allow ;;     # an explicitly different tool is governed by Claude Code permissions
esac

CMD="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')"
[ -n "$CMD" ] || allow

# Missing policy files => fail closed.
if [ ! -f "$DENY_FILE" ] || [ ! -f "$ALLOW_FILE" ]; then
  deny "White Rabbit guard: policy files missing at $POLICY_DIR — failing closed."
fi

# --- Check 1: denylist (mutation signatures anywhere in the command) ---
while IFS= read -r pat; do
  case "$pat" in ''|'#'*) continue;; esac
  if printf '%s' "$CMD" | grep -Eq -- "$pat"; then
    deny "White Rabbit guard: command matches a denied (mutating) pattern — blocked (read-only)."
  fi
done < "$DENY_FILE"

# Remove safe redirections (fd dups like 2>&1, and /dev/null sinks) ONCE. The result is
# reused by Check 2 and Check 3 so that an `&` inside `2>&1` is never mistaken for an operator.
CLEAN="$(printf '%s' "$CMD" | sed -E 's#[0-9]*>>?[[:space:]]*/dev/null##g; s#[0-9]*>&[0-9]+##g')"

# --- Check 2: output redirection to a file (allow /dev/null sinks and fd dups only) ---
if printf '%s' "$CLEAN" | grep -q '>'; then
  deny "White Rabbit guard: output redirection to a file is not allowed (read-only)."
fi

# --- Check 3: allowlist (first token of every pipeline segment) ---
# Split CLEAN (not CMD) so stripped fd-redirects don't create spurious segments.
SEGMENTS="$(printf '%s' "$CLEAN" | sed -E 's/\|\||&&|;|\||&/\n/g')"
while IFS= read -r seg; do
  seg="$(printf '%s' "$seg" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  [ -n "$seg" ] || continue
  # Strip leading VAR=val environment assignments.
  seg="$(printf '%s' "$seg" | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)+//')"
  first="$(printf '%s' "$seg" | awk '{print $1}')"
  [ -n "$first" ] || continue
  # Vetted WR analysis script: allow ONLY when the first token resolves (against the guard's
  # own cwd — the plugin root; the model cannot `cd`, since `cd` is not allowlisted) to an exact
  # canonical script path. A planted /evil/correlate.sh or a bare `cve_scan.sh` resolves
  # elsewhere and is NOT allowed here — it falls through to the basename allowlist and is denied.
  if [ -n "$WR_ROOT_DIR" ]; then
    if fdir="$(cd "$(dirname -- "$first")" 2>/dev/null && pwd)"; then
      canon="$fdir/$(basename -- "$first")"
      case "$canon" in
        "$WR_CORRELATOR"|"$WR_CVE_SCANNER"|"$WR_SERVICE_EOL"|"$WR_EXT_LIST"|"$WR_VALIDATE_FINDINGS"|"$WR_RENDER_HTML") continue ;;
      esac
    fi
  fi
  first="$(basename -- "$first")"
  grep -Fxq -- "$first" "$ALLOW_FILE" && continue
  if [ -f "$LOCAL_ALLOW_FILE" ] && grep -Fxq -- "$first" "$LOCAL_ALLOW_FILE"; then
    continue
  fi
  deny "White Rabbit guard: '$first' is not on the read-only allowlist — blocked. If this is an extension binary you trust, add '$first' to policy/allowed-commands.local.txt."
done <<EOF
$SEGMENTS
EOF

# Passed all three checks.
allow
