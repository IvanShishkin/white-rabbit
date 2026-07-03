#!/usr/bin/env bash
set -euo pipefail

# White Rabbit extensions discovery (read-only).
#
# Usage: list.sh [extensions_dir]     default: <repo_root>/extensions
# Stdout: one TSV row per discovered extension:
#   name<TAB>resolved_path<TAB>manifest_path<TAB>description
# name is the entry name in extensions/ (the symlink name — what the user types in /wr <name>).
# Manifest priority: wr-extension.md > CLAUDE.md > README.md.
# Broken symlinks and manifest-less entries are skipped with a warning on stderr.
# "No extensions" is not an error: empty stdout, exit 0.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="${1:-$(dirname "$(dirname "$SCRIPT_DIR")")/extensions}"

[ -d "$EXT_DIR" ] || exit 0

# description: frontmatter `description:` if present, else the first non-empty
# non-heading body line. Tabs are flattened so the TSV stays well-formed.
extract_desc() {
  awk '
    { sub(/\r$/, "") }                # tolerate CRLF manifests
    NR==1 && $0=="---" { fm=1; next }
    fm==1 {
      if ($0=="---") { fm=2; next }
      if ($0 ~ /^description:/) { sub(/^description:[ \t]*/, ""); gsub(/\t/, " "); done=1; print; exit }
      # remember a fallback in case the fence never closes
      if (fb=="" && $0 !~ /^[ \t]*$/ && $0 !~ /^#/ && $0 !~ /^---/) fb=$0
      next
    }
    /^[ \t]*$/ { next }
    /^#/ { next }
    { gsub(/\t/, " "); done=1; print; exit }
    END { if (!done && fb!="") { gsub(/\t/, " ", fb); print fb } }
  ' "$1"
}

for entry in "$EXT_DIR"/*; do
  if [ ! -e "$entry" ]; then
    # broken symlink (or an unmatched glob, which is not a symlink — just skip)
    [ -L "$entry" ] && echo "wr-extensions: skipping '$(basename "$entry")' — broken symlink" >&2
    continue
  fi
  name="$(basename "$entry")"
  [ "$name" = "README.md" ] && continue
  [ -d "$entry" ] || continue
  if ! dir="$(cd "$entry" 2>/dev/null && pwd -P)"; then
    echo "wr-extensions: skipping '$name' — target directory is not readable" >&2
    continue
  fi
  manifest=""
  for cand in wr-extension.md CLAUDE.md README.md; do
    [ -f "$dir/$cand" ] && { manifest="$dir/$cand"; break; }
  done
  if [ -z "$manifest" ]; then
    echo "wr-extensions: skipping '$name' — no manifest (wr-extension.md/CLAUDE.md/README.md)" >&2
    continue
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$dir" "$manifest" "$(extract_desc "$manifest")"
done

exit 0
