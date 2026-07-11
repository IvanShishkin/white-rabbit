#!/usr/bin/env bash
# White Rabbit — findings.json validator. STRICTLY READ-ONLY (reads one file, prints stdout).
#   scripts/report/validate_findings.sh <findings.json>
# Exit 0 = valid; 1 = invalid (WR-VALIDATE error lines); 2 = usage / unreadable / no jq.
set -uo pipefail

F="${1:-}"
if [ -z "$F" ] || [ ! -r "$F" ]; then
  printf 'WR-VALIDATE: input not readable or missing: %s\n' "${F:-<empty>}" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'WR-VALIDATE: jq not found\n' >&2
  exit 2
fi

# Unparseable JSON is a hard failure (exit 1), not a crash.
if ! jq -e . "$F" >/dev/null 2>&1; then
  printf 'WR-VALIDATE: FAIL\nWR-VALIDATE: not valid JSON\n'
  exit 1
fi

ERRORS="$(jq -r '
  def sev:      ["critical","high","medium","low","info"];
  def areas:    ["ssh","firewall","ports","access","persistence","patching","sysctl","docker","auth-log","web","cross","cve"];
  def statuses: ["new","unchanged","resolved"];
  [
    (["target","collected","summary","findings"][] as $k | select((has($k))|not) | "missing top-level key: \($k)"),
    (["critical","high","medium","low","info"][] as $s
       | select((.summary[$s]? | type) != "number") | "summary.\($s) missing or not a number"),
    ((.findings // []) | to_entries[] | .key as $i | .value as $f
       | (["id","severity","area","title","evidence","why","fix","status"][] as $k
            | select(($f|has($k))|not) | "finding[\($i)] missing key: \($k)"),
         (select(($f.severity as $v | sev | index($v)) == null)      | "finding[\($i)] bad severity: \($f.severity)"),
         (select(($f.area as $v | areas | index($v)) == null)        | "finding[\($i)] bad area: \($f.area)"),
         (select(($f.status as $v | statuses | index($v)) == null)   | "finding[\($i)] bad status: \($f.status)"),
         (select(($f.evidence? | type) != "array")                  | "finding[\($i)] evidence not an array")),
    (["critical","high","medium","low","info"][] as $s
       | ((.findings // []) | map(select(.severity==$s)) | length) as $actual
       | select((.summary[$s]? // -1) != $actual)
       | "summary.\($s)=\(.summary[$s]) but findings has \($actual)")
  ] | .[]
' "$F" 2>/dev/null)"

if [ -n "$ERRORS" ]; then
  printf 'WR-VALIDATE: FAIL\n'
  printf '%s\n' "$ERRORS" | sed 's/^/WR-VALIDATE: /'
  exit 1
fi
printf 'WR-VALIDATE: OK (%s findings)\n' "$(jq '.findings | length' "$F")"
exit 0
