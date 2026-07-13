#!/usr/bin/env bash
# White Rabbit — structured diff of two findings.json sidecars for report-driven re-checks
# (`/wr retry`). STRICTLY READ-ONLY: reads two JSON files, prints to stdout, writes nothing.
#   scripts/report/diff_findings.sh <old findings.json|dir> <new findings.json|dir>
# Joins findings by their stable `id` and classifies each:
#   RESOLVED   — in old, gone from new
#   STILL-OPEN — in both (flags a severity change with `was=<old-sev>`)
#   NEW        — in new, absent from old
# Emits a `WR-DIFF-SUMMARY:` line then one `WR-DIFF:` line per finding (NEW → STILL-OPEN →
# RESOLVED, each by severity). Deterministic; jq-only. Exit 0 ok / 2 unreadable input / 1 bad JSON.
set -uo pipefail

resolve() { # a bundle dir resolves to its findings.json
  local p="$1"
  if [ -n "$p" ] && [ -d "$p" ]; then printf '%s/findings.json' "$p"; else printf '%s' "$p"; fi
}
OLD="$(resolve "${1:-}")"
NEW="$(resolve "${2:-}")"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }

if [ -z "${1:-}" ] || [ -z "${2:-}" ] || [ ! -r "$OLD" ] || [ ! -r "$NEW" ]; then
  section diff
  note "need two readable findings.json inputs (old, new); got '${1:-<empty>}' '${2:-<empty>}'"
  section end
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  section diff; note "jq not found"; section end; exit 2
fi
if ! jq -e . "$OLD" >/dev/null 2>&1 || ! jq -e . "$NEW" >/dev/null 2>&1; then
  section diff; note "one or both inputs are not valid JSON"; section end; exit 1
fi

section diff
jq -rn --slurpfile o "$OLD" --slurpfile n "$NEW" '
  def sev: {critical:0,high:1,medium:2,low:3,info:4}[.];
  (($o[0].findings) // []) as $of
  | (($n[0].findings) // []) as $nf
  | ($of | map({(.id): .}) | add // {}) as $om
  | ($nf | map({(.id): .}) | add // {}) as $nm
  | ( [ $nf[] | select($om[.id] == null)        | {st:"NEW",        sr:0, f:.} ]
    + [ $nf[] | select($om[.id] != null)        | {st:"STILL-OPEN", sr:1, f:., old:$om[.id]} ]
    + [ $of[] | select($nm[.id] == null)        | {st:"RESOLVED",   sr:2, f:.} ]
    ) as $rows
  | "WR-DIFF-SUMMARY: new=\([$rows[]|select(.st=="NEW")]|length) still_open=\([$rows[]|select(.st=="STILL-OPEN")]|length) resolved=\([$rows[]|select(.st=="RESOLVED")]|length)",
    ( $rows
      | sort_by(.sr, (.f.severity | sev))
      | .[]
      | (if .st=="STILL-OPEN" and (.old.severity != .f.severity) then " was=\(.old.severity)" else "" end) as $chg
      | "WR-DIFF: \(.f.id) \(.st) sev=\(.f.severity)\($chg) title=\(.f.title)"
    )
'
section end
