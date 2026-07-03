#!/usr/bin/env bash
# White Rabbit — OS-package CVE scan. STRICTLY READ-ONLY (reads one local dump, writes
# nothing but stdout; never touches the audited host).
#   scripts/analyze/cve_scan.sh <snapshot_dump>
# Matches the snapshot's `packages` inventory (collector v4+) against OSV.dev, then
# prioritizes: CISA KEV → EPSS → OSV severity. Only actionable findings (a fixed version
# exists) are emitted as WR-CVE lines; no-fix matches are counted in a note.
#
# POSTURE NOTE (outbound traffic): in live mode this script makes outbound HTTPS requests
# from the AUDITOR machine (never from the audited host) to api.osv.dev, api.first.org
# (EPSS) and www.cisa.gov (KEV). What leaves: OS package names+versions and CVE ids —
# public, low-sensitivity data. No hostnames, no IPs, no secrets. Any source being
# unreachable degrades to a WR-NOTE; nothing is invented.
# Test seam: WR_CVE_SOURCE=<fixture dir> replaces every network call with local files
# (querybatch.json, vulns/<id>.json, epss.json, kev.json) — tests never touch the network.
set -uo pipefail

DUMP="${1:-${WR_PKG_DUMP:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# VEX file: accepted / not-applicable CVEs with a justification. One rule per line:
#   <CVE-id> <source-pkg|*> <justification…>
VEX_FILE="${WR_VEX:-$ROOT_DIR/targets/vex.txt}"
TAB="$(printf '\t')"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }

if [ -z "$DUMP" ] || [ ! -r "$DUMP" ]; then
  section cve
  note "input dump not readable or missing: '${DUMP:-<empty>}' — cannot scan"
  section end
  exit 1
fi

sec_lines() { # $1 dump, $2 section name — lines inside that WR-SECTION
  awk -v want="$2" '
    /^===== WR-SECTION:/ { insec = ($0 ~ ("WR-SECTION: " want " ")) ? 1 : 0; next }
    insec { print }
  ' "$1" 2>/dev/null
}

# ---- packages: dedup to SOURCE package + SOURCE version (advisories are keyed by source) ----
PKG_LIST="$(sec_lines "$DUMP" packages \
  | awk -F'\t' 'NF==4 {print $3 "\t" $4} NF==2 {print $1 "\t" $2}' | sort -u)"
if [ -z "$PKG_LIST" ]; then
  section cve
  note "no package inventory in the dump (packages section missing/empty — need collector v4+)"
  section end
  exit 0
fi
NSRC="$(printf '%s\n' "$PKG_LIST" | grep -ac .)"

# ---- ecosystem from os-release lines the collector embeds in `meta` ----
OS_ID="$(grep -aE '^ID=' "$DUMP" 2>/dev/null | head -1 | sed -E 's/^ID=//; s/"//g')"
OS_VER="$(grep -aE '^VERSION_ID=' "$DUMP" 2>/dev/null | head -1 | sed -E 's/^VERSION_ID=//; s/"//g')"
case "$OS_ID" in
  ubuntu)
    # Even-year .04 releases are LTS; OSV names their ecosystem "Ubuntu:<ver>:LTS".
    case "$OS_VER" in
      20.04|22.04|24.04|26.04|28.04) ECO="Ubuntu:${OS_VER}:LTS" ;;
      *)                             ECO="Ubuntu:${OS_VER}" ;;
    esac ;;
  debian)    ECO="Debian:${OS_VER%%.*}" ;;
  almalinux) ECO="AlmaLinux:${OS_VER%%.*}" ;;
  rocky)     ECO="Rocky Linux:${OS_VER%%.*}" ;;
  *)
    section cve
    note "unsupported distro for CVE matching: '${OS_ID:-unknown}' — scan skipped (no guessing)"
    section end
    exit 0 ;;
esac

# ---- source fetchers: fixture dir (tests, offline) or live HTTPS (auditor-side only) ----
fetch_osv_batch() { # $1 = JSON body {"queries": [...]}
  if [ -n "${WR_CVE_SOURCE:-}" ]; then cat "$WR_CVE_SOURCE/querybatch.json" 2>/dev/null
  else curl -sS --max-time 30 -H 'Content-Type: application/json' -d "$1" \
         'https://api.osv.dev/v1/querybatch' 2>/dev/null
  fi
}
fetch_osv_vuln() { # $1 = vuln id
  if [ -n "${WR_CVE_SOURCE:-}" ]; then cat "$WR_CVE_SOURCE/vulns/$1.json" 2>/dev/null
  else curl -sS --max-time 30 "https://api.osv.dev/v1/vulns/$1" 2>/dev/null
  fi
}
fetch_epss() { # $1 = comma-separated CVE ids
  if [ -n "${WR_CVE_SOURCE:-}" ]; then cat "$WR_CVE_SOURCE/epss.json" 2>/dev/null
  else curl -sS --max-time 30 "https://api.first.org/data/v1/epss?cve=$1" 2>/dev/null
  fi
}
fetch_kev() {
  if [ -n "${WR_CVE_SOURCE:-}" ]; then cat "$WR_CVE_SOURCE/kev.json" 2>/dev/null
  else curl -sS --max-time 60 \
         'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' 2>/dev/null
  fi
}

section cve
note "ecosystem: $ECO"

# ---- OSV querybatch (chunks of 900; API cap is 1000 queries per call) ----
QUERIES="$(printf '%s\n' "$PKG_LIST" | jq -R -s --arg eco "$ECO" \
  '[split("\n")[] | select(length != 0) | split("\t")
    | {package: {name: .[0], ecosystem: $eco}, version: .[1]}]')"
N="$(printf '%s' "$QUERIES" | jq 'length')"
MATCHES=""
OSV_OK=1
i=0
while [ "$i" -lt "$N" ]; do
  chunk="$(printf '%s' "$QUERIES" | jq -c ".[$i:$((i+900))]")"
  resp="$(fetch_osv_batch "{\"queries\":$chunk}")"
  if ! printf '%s' "$resp" | jq -e '.results | type == "array"' 1>/dev/null 2>&1; then
    OSV_OK=0; break
  fi
  m="$(printf '%s' "$resp" | jq -r --argjson q "$chunk" '
        .results | to_entries[] | .key as $i
        | ((.value.vulns // [])[]? | .id) as $v
        | [$q[$i].package.name, $q[$i].version, $v] | @tsv' 2>/dev/null)"
  [ -n "$m" ] && MATCHES="${MATCHES}${m}
"
  i=$((i+900))
done

if [ "$OSV_OK" -eq 0 ]; then
  note "cve source (OSV.dev) unreachable or returned invalid data — CVE matching skipped, nothing invented"
  section end
  exit 0
fi

MATCHES="$(printf '%s' "$MATCHES" | sort -u | grep -a . || true)"
if [ -z "$MATCHES" ]; then
  note "no known vulnerabilities matched for $NSRC source packages"
  section end
  note "cve scan complete"
  exit 0
fi
NMATCH="$(printf '%s\n' "$MATCHES" | grep -ac .)"

# ---- per-vulnerability details (fetched once per unique id) ----
DETAILS=""
MISSING_DETAILS=0
while IFS= read -r vid; do
  [ -n "$vid" ] || continue
  dj="$(fetch_osv_vuln "$vid" | jq -c '.' 2>/dev/null)"
  if [ -z "$dj" ] || [ "$dj" = "null" ]; then
    MISSING_DETAILS=$((MISSING_DETAILS+1)); continue
  fi
  DETAILS="${DETAILS}${vid}${TAB}${dj}
"
done <<EOF
$(printf '%s\n' "$MATCHES" | cut -f3 | sort -u)
EOF

# ---- rows: pkg, version, CVE id (alias-resolved), OSV severity, fixed version ----
ROWS=""
NOFIX=""
while IFS="$TAB" read -r pkg ver vid; do
  [ -n "$pkg" ] || continue
  dj="$(printf '%s\n' "$DETAILS" | grep -a "^${vid}${TAB}" | head -1 | cut -f2-)"
  [ -n "$dj" ] || continue
  cve="$(printf '%s' "$dj" | jq -r '([.aliases[]? | select(startswith("CVE-"))][0]) // .id')"
  # Fixed version: prefer the exact ecosystem match; fall back to a name-only match
  # (OSV sometimes carries sub-ecosystem labels like "Ubuntu:Pro:…").
  fixed="$(printf '%s' "$dj" | jq -r --arg p "$pkg" --arg e "$ECO" '
    ([.affected[]? | select(.package.name == $p and .package.ecosystem == $e)
      | .ranges[]? | .events[]? | .fixed // empty][0])
    // ([.affected[]? | select(.package.name == $p)
      | .ranges[]? | .events[]? | .fixed // empty][0])
    // empty')"
  dbsev="$(printf '%s' "$dj" | jq -r '.database_specific.severity // empty' \
           | tr '[:upper:]' '[:lower:]')"
  if [ -z "$fixed" ]; then
    NOFIX="${NOFIX}${cve} (${pkg})
"
    continue
  fi
  ROWS="${ROWS}${pkg}${TAB}${ver}${TAB}${cve}${TAB}${dbsev:--}${TAB}${fixed}
"
done <<EOF
$MATCHES
EOF
# Dedup by pkg+CVE (the same CVE can arrive via several advisory ids, e.g. USN + CVE).
ROWS="$(printf '%s' "$ROWS" | sort -t"$TAB" -k1,1 -k3,3 -u | grep -a . || true)"

# ---- EPSS (FIRST.org), chunks of 100 CVEs per request ----
CVES="$(printf '%s\n' "$ROWS" | cut -f3 | grep -a . | sort -u || true)"
EPSS_TSV=""
EPSS_OK=1
if [ -n "$CVES" ]; then
  total="$(printf '%s\n' "$CVES" | grep -ac .)"
  j=1
  while [ "$j" -le "$total" ]; do
    endl=$((j+99))
    csv="$(printf '%s\n' "$CVES" | sed -n "${j},${endl}p" | paste -sd, -)"
    eresp="$(fetch_epss "$csv")"
    if printf '%s' "$eresp" | jq -e '.data | type == "array"' 1>/dev/null 2>&1; then
      EPSS_TSV="${EPSS_TSV}$(printf '%s' "$eresp" \
        | jq -r '.data[]? | [.cve, (.epss | tostring)] | @tsv')
"
    else
      EPSS_OK=0; break
    fi
    j=$((endl+1))
  done
fi

# ---- CISA KEV ----
KEV_LIST=""
KEV_OK=1
kresp="$(fetch_kev)"
if printf '%s' "$kresp" | jq -e '.vulnerabilities | type == "array"' 1>/dev/null 2>&1; then
  KEV_LIST="$(printf '%s' "$kresp" | jq -r '.vulnerabilities[]? | .cveID // empty')"
else
  KEV_OK=0
fi

# ---- VEX rules ----
VEX_RULES=""
if [ -r "$VEX_FILE" ]; then
  VEX_RULES="$(grep -avE '^[[:space:]]*(#|$)' "$VEX_FILE" 2>/dev/null || true)"
fi

# ---- assemble, prioritize, emit ----
# Severity ladder (see knowledge/checks/cve.md): KEV → crit, regardless of anything else;
# EPSS above 0.5 or OSV severity critical → high; EPSS above 0.1 or OSV severity high →
# medium; else low. A degraded source ("-") never escalates and never silences a note.
OUT=""
SUPP=""
while IFS="$TAB" read -r pkg ver cve dbsev fixed; do
  [ -n "$pkg" ] || continue
  vexreason="$(printf '%s\n' "$VEX_RULES" | awk -v c="$cve" -v p="$pkg" '
    $1==c && ($2==p || $2=="*") { out=""; for(i=3;i<=NF;i++) out=out (i==3?"":" ") $i; print out; exit }')"
  if [ -n "$vexreason" ]; then
    SUPP="${SUPP}WR-CVE-SUPPRESSED: ${pkg} ${cve} reason=${vexreason}
"
    continue
  fi
  epss="-"
  if [ "$EPSS_OK" -eq 1 ]; then
    e="$(printf '%s\n' "$EPSS_TSV" | awk -F'\t' -v c="$cve" '$1==c {print $2; exit}')"
    [ -n "$e" ] && epss="$(printf '%s' "$e" | awk '{printf "%.2f", $1+0}')"
  fi
  kev="-"
  if [ "$KEV_OK" -eq 1 ]; then
    if printf '%s\n' "$KEV_LIST" | grep -qxF "$cve"; then kev=yes; else kev=no; fi
  fi
  sev=low; rank=3
  if [ "$kev" = yes ]; then sev=crit; rank=0
  elif [ "$epss" != "-" ] && awk -v e="$epss" 'BEGIN{exit !(0.5 < e+0)}'; then sev=high; rank=1
  elif [ "$dbsev" = critical ]; then sev=high; rank=1
  elif { [ "$epss" != "-" ] && awk -v e="$epss" 'BEGIN{exit !(0.1 < e+0)}'; } \
       || [ "$dbsev" = high ]; then sev=medium; rank=2
  fi
  OUT="${OUT}${rank}${TAB}${epss}${TAB}WR-CVE: ${pkg} ${ver} ${cve} sev=${sev} epss=${epss} kev=${kev} fixed=${fixed}
"
done <<EOF
$ROWS
EOF

NACT="$(printf '%s' "$OUT" | grep -ac . || true)"
if [ -n "$OUT" ]; then
  printf '%s' "$OUT" | sort -t"$TAB" -k1,1n -k2,2gr | cut -f3-
else
  note "no actionable (fixable) vulnerabilities among the matches"
fi
[ -n "$SUPP" ] && printf '%s' "$SUPP"
[ "$EPSS_OK" -eq 1 ] || note "EPSS source (FIRST.org) unavailable — epss=- for all findings (prioritization degraded)"
[ "$KEV_OK" -eq 1 ]  || note "KEV source (CISA) unavailable — kev=- for all findings (known-exploited escalation degraded)"
[ "$MISSING_DETAILS" -eq 0 ] || note "$MISSING_DETAILS vulnerability record(s) could not be fetched from OSV.dev — those matches are not shown"
if [ -n "$NOFIX" ]; then
  nf="$(printf '%s' "$NOFIX" | grep -ac .)"
  note "$nf matched vulnerability(ies) have no fixed version yet (not actionable, not shown): $(printf '%s' "$NOFIX" | head -10 | paste -sd';' - | sed 's/;/; /g')"
fi
note "scanned $NSRC source packages; $NMATCH vulnerability matches; $NACT actionable"
section end
note "cve scan complete"
