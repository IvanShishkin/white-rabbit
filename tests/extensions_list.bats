#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/extensions/list.sh"

setup() {
  WORK="$(mktemp -d)"
  EXT="$WORK/extensions"
  PROJ="$WORK/projects"
  mkdir -p "$EXT" "$PROJ"
}

teardown() { [ -n "${WORK:-}" ] && rm -rf "$WORK" || true; }

# make_ext <name> — create a project dir and symlink extensions/<name> to it; prints project path
make_ext() {
  local dir="$PROJ/$1"
  mkdir -p "$dir"
  ln -s "$dir" "$EXT/$1"
  echo "$dir"
}

# col <line> <n> — print the n-th TAB-separated column
col() { echo "$1" | awk -F'\t' -v n="$2" '{print $n}'; }

# stdout_only — run the script keeping stdout, discarding stderr
stdout_only() { run bash -c "bash '$SCRIPT' '$1' 2>/dev/null"; }

@test "missing extensions dir: empty stdout, exit 0" {
  run bash "$SCRIPT" "$WORK/nonexistent"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "empty extensions dir: empty stdout, exit 0" {
  run bash "$SCRIPT" "$EXT"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "symlinked project with wr-extension.md: TSV row, description from frontmatter" {
  local dir; dir="$(make_ext example-scanner)"
  cat > "$dir/wr-extension.md" <<'EOF'
---
name: example-scanner
description: Go security scanner for malware and webshells
commands: example-scanner
---
# Example-scanner
Body text that must NOT become the description.
EOF
  stdout_only "$EXT"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | awk -F'\t' '$1=="example-scanner"')"
  [ -n "$line" ]
  [ "$(col "$line" 2)" = "$(cd "$dir" && pwd -P)" ]
  [ "$(basename "$(col "$line" 3)")" = "wr-extension.md" ]
  [ "$(col "$line" 4)" = "Go security scanner for malware and webshells" ]
}

@test "manifest priority: wr-extension.md wins over CLAUDE.md" {
  local dir; dir="$(make_ext dual)"
  printf -- '---\ndescription: from manifest\n---\n' > "$dir/wr-extension.md"
  printf '# CLAUDE\nfrom claude md\n' > "$dir/CLAUDE.md"
  stdout_only "$EXT"
  [ "$status" -eq 0 ]
  local line; line="$(echo "$output" | awk -F'\t' '$1=="dual"')"
  [ "$(basename "$(col "$line" 3)")" = "wr-extension.md" ]
}

@test "manifest priority: CLAUDE.md wins over README.md" {
  local dir; dir="$(make_ext clonly)"
  printf '# Tool\nClaude-facing description line.\n' > "$dir/CLAUDE.md"
  printf '# Tool\nreadme line\n' > "$dir/README.md"
  stdout_only "$EXT"
  local line; line="$(echo "$output" | awk -F'\t' '$1=="clonly"')"
  [ "$(basename "$(col "$line" 3)")" = "CLAUDE.md" ]
}

@test "fallback description: first non-empty non-heading line of README" {
  local dir; dir="$(make_ext plain)"
  cat > "$dir/README.md" <<'EOF'
# Plain Tool

Scans things in a plain way.

More text.
EOF
  stdout_only "$EXT"
  local line; line="$(echo "$output" | awk -F'\t' '$1=="plain"')"
  [ "$(col "$line" 4)" = "Scans things in a plain way." ]
}

@test "plain directory (not a symlink) is also listed" {
  mkdir -p "$EXT/indir"
  printf '# In\nIn-tree extension.\n' > "$EXT/indir/CLAUDE.md"
  stdout_only "$EXT"
  local line; line="$(echo "$output" | awk -F'\t' '$1=="indir"')"
  [ -n "$line" ]
}

@test "broken symlink: skipped with a stderr warning, exit 0" {
  ln -s "$PROJ/gone" "$EXT/ghost"
  run bash "$SCRIPT" "$EXT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'ghost'          # warning mentions the entry (stderr is in $output)
  stdout_only "$EXT"
  [ -z "$output" ]                          # but stdout has no row for it
}

@test "project without any manifest: skipped with a stderr warning, exit 0" {
  make_ext bare >/dev/null
  run bash "$SCRIPT" "$EXT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'bare'
  stdout_only "$EXT"
  [ -z "$output" ]
}

@test "unreadable extension target: skipped with warning, later extensions still listed, exit 0" {
  local dir_a; dir_a="$(make_ext aaa)"
  printf '# A\ndesc a\n' > "$dir_a/README.md"
  local dir_z; dir_z="$(make_ext zzz)"
  printf '# Z\ndesc z\n' > "$dir_z/README.md"
  chmod 000 "$dir_a"
  run bash "$SCRIPT" "$EXT"
  chmod 755 "$dir_a"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'aaa'                       # warning names the entry
  echo "$output" | awk -F'\t' '$1=="zzz"' | grep -q zzz  # zzz row survived
}

@test "CRLF manifest: frontmatter still detected, description clean of CR" {
  local dir; dir="$(make_ext crlf)"
  printf -- '---\r\ndescription: crlf desc\r\n---\r\nBody line.\r\n' > "$dir/wr-extension.md"
  stdout_only "$EXT"
  local line; line="$(echo "$output" | awk -F'\t' '$1=="crlf"')"
  [ "$(col "$line" 4)" = "crlf desc" ]
}

@test "unterminated frontmatter: falls back to first content line instead of empty description" {
  local dir; dir="$(make_ext unterm)"
  printf -- '---\nname: unterm\nno closing fence\n' > "$dir/wr-extension.md"
  stdout_only "$EXT"
  local line; line="$(echo "$output" | awk -F'\t' '$1=="unterm"')"
  [ "$(col "$line" 4)" = "name: unterm" ]
}

@test "extensions/README.md is not an extension" {
  printf '# Extensions\nconvention docs\n' > "$EXT/README.md"
  stdout_only "$EXT"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
