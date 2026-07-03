#!/usr/bin/env bats

ALLOW="${BATS_TEST_DIRNAME}/../policy/allowed-commands.txt"
DENY="${BATS_TEST_DIRNAME}/../policy/denied-patterns.txt"

@test "allowlist exists and contains core read-only commands" {
  [ -f "$ALLOW" ]
  # awk/sed/env/xargs removed from allowlist in C-1 hardening (they run/write via allowlisted tools)
  for c in ss cat journalctl dpkg grep; do
    grep -Fxq "$c" "$ALLOW"
  done
}

@test "denylist exists and is non-empty (ignoring comments/blanks)" {
  [ -f "$DENY" ]
  local n
  n="$(grep -Ev '^[[:space:]]*($|#)' "$DENY" | wc -l | tr -d ' ')"
  [ "$n" -gt 0 ]
}

@test "every denied pattern is a valid extended regex" {
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue;; esac
    # grep -E exits 0 (match) or 1 (no match) for a VALID regex; 2 means the regex itself is invalid.
    rc=0
    printf '' | grep -Eq -- "$pat" || rc=$?
    [ "$rc" -ne 2 ]
  done < "$DENY"
}

@test "denylist blocks rm and allowlist omits it" {
  printf '%s' "rm -rf /tmp/x" | grep -Eq -f <(grep -Ev '^[[:space:]]*($|#)' "$DENY")
  ! grep -Fxq "rm" "$ALLOW"
}
