#!/usr/bin/env bash
# White Rabbit — service version currency / EOL check. STRICTLY READ-ONLY (reads one local dump,
# writes nothing but stdout; never touches the audited host).
#   scripts/analyze/service_eol.sh <snapshot_dump>
# Reads the snapshot's `packages` inventory (collector v4+), picks out network-facing / important
# services (nginx, apache, php, mysql, mariadb, postgresql, redis, nodejs, openssl), and checks
# each installed version against endoflife.date — flagging end-of-life and behind-latest versions.
# This is the deterministic counterpart to the model's ad-hoc "is this version old?" judgement,
# and it catches what the CVE scan cannot (OSV is blind on an EOL host without ESM).
#
# POSTURE NOTE (outbound traffic): in live mode this makes outbound HTTPS requests from the
# AUDITOR machine (never from the audited host) to endoflife.date. What leaves: public product
# names + version cycles. No hostnames, no IPs, no secrets. A source being unreachable degrades
# to a WR-NOTE; nothing is invented.
# Test seam: WR_EOL_SOURCE=<fixture dir> replaces every network call with local files
# (<product>.json); tests never touch the network. WR_EOL_TODAY pins "today" for eol-date checks.
set -uo pipefail

DUMP="${1:-${WR_PKG_DUMP:-}}"
TAB="$(printf '\t')"
TODAY="${WR_EOL_TODAY:-$(date -u '+%Y-%m-%d' 2>/dev/null)}"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }

if [ -z "$DUMP" ] || [ ! -r "$DUMP" ]; then
  section service_eol
  note "input dump not readable or missing: '${DUMP:-<empty>}' — cannot check"
  section end
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  section service_eol
  note "jq not found — cannot check"
  section end
  exit 1
fi

sec_lines() { # $1 dump, $2 section name — lines inside that WR-SECTION
  awk -v want="$2" '
    /^===== WR-SECTION:/ { insec = ($0 ~ ("WR-SECTION: " want " ")) ? 1 : 0; next }
    insec { print }
  ' "$1" 2>/dev/null
}

# --- map a binary package name to an endoflife.date product slug (empty = not tracked) ---
map_product() {
  case "$1" in
    nginx|nginx-core|nginx-full|nginx-light|nginx-extras) echo nginx ;;
    php[0-9]*)                                             echo php ;;
    apache2)                                               echo apache-http-server ;;
    mysql-server*|mysql-community-server*)                 echo mysql ;;
    mariadb-server*)                                       echo mariadb ;;
    postgresql-[0-9]*)                                     echo postgresql ;;
    redis-server|redis)                                    echo redis ;;
    nodejs)                                                echo nodejs ;;
    libssl[0-9]*|openssl)                                  echo openssl ;;
    *)                                                     echo "" ;;
  esac
}

# --- strip a Debian/Ubuntu version to its upstream part: drop epoch, then cut at -, +, ~ ---
upstream_ver() {
  local v="${1#*:}"          # strip "1:" epoch if present
  v="${v%%-*}"; v="${v%%+*}"; v="${v%%~*}"
  printf '%s' "$v"
}

fetch_eol_product() { # $1 = product slug
  if [ -n "${WR_EOL_SOURCE:-}" ]; then cat "$WR_EOL_SOURCE/$1.json" 2>/dev/null
  else curl -sS --max-time 20 "https://endoflife.date/api/$1.json" 2>/dev/null
  fi
}

section service_eol
note "source: endoflife.date · today=$TODAY"

# --- candidate (product, upstream-version) pairs from the packages inventory ---
PKG_SECTION="$(sec_lines "$DUMP" packages | awk -F'\t' 'NF>=2 && $1 !~ /^(pkg_manager|WR-NOTE)/ {print $1 "\t" $2}')"
if [ -z "$PKG_SECTION" ]; then
  note "no package inventory in the dump (packages section missing/empty — need collector v4+)"
  section end
  exit 0
fi

# Collect unique product<TAB>upstream pairs (dedup so php7.2-cli/-fpm/-common map once).
PAIRS=""
while IFS="$TAB" read -r name ver; do
  [ -n "$name" ] || continue
  prod="$(map_product "$name")"
  [ -n "$prod" ] || continue
  up="$(upstream_ver "$ver")"
  [ -n "$up" ] || continue
  PAIRS="${PAIRS}${prod}${TAB}${up}
"
done <<EOF
$PKG_SECTION
EOF
PAIRS="$(printf '%s' "$PAIRS" | sort -u | grep -a . || true)"
if [ -z "$PAIRS" ]; then
  note "no tracked network-facing services found in the inventory (nginx/apache/php/mysql/…)"
  section end
  exit 0
fi

ROWS=""
SRC_OK=1
while IFS="$TAB" read -r prod up; do
  [ -n "$prod" ] || continue
  json="$(fetch_eol_product "$prod")"
  if [ -z "$json" ] || ! printf '%s' "$json" | jq -e 'type == "array"' >/dev/null 2>&1; then
    note "$prod: endoflife.date returned no data — $prod not version-checked (source unavailable or product unknown)"
    SRC_OK=0
    continue
  fi
  # Longest cycle whose string is a prefix of the installed upstream version.
  row="$(printf '%s' "$json" | jq -r --arg u "$up" --arg p "$prod" --arg today "$TODAY" '
    ( [ .[] | select(.cycle as $c | ($u | startswith($c))) ] | sort_by(.cycle | length) | last ) as $cyc
    | if $cyc == null then empty
      else
        ($cyc.eol) as $eol
        | ($cyc.latest // "-") as $lat
        | (if      ($eol == true)  then "eol"
           elif ($eol == false) or ($eol == null) then (if ($lat != "-" and $u != $lat) then "outdated" else "current" end)
           elif ($eol | type) == "string" then (if ($eol < $today) then "eol" elif ($lat != "-" and $u != $lat) then "outdated" else "current" end)
           else "current" end) as $st
        | ( if $st=="eol" then 0 elif $st=="outdated" then 1 else 2 end ) as $rank
        | "\($rank)\t\($p)\t\($u)\t\($cyc.cycle)\t\(if ($eol|type)=="string" then $eol else ($eol|tostring) end)\t\($lat)\t\($st)"
      end')"
  if [ -z "$row" ]; then
    note "$prod $up: no matching release cycle on endoflife.date — not version-checked"
    continue
  fi
  ROWS="${ROWS}${row}
"
done <<EOF
$PAIRS
EOF

ROWS="$(printf '%s' "$ROWS" | grep -a . || true)"
if [ -n "$ROWS" ]; then
  # sort by rank (eol → outdated → current), then product; drop the rank column
  printf '%s\n' "$ROWS" | sort -t"$TAB" -k1,1n -k2,2 \
    | while IFS="$TAB" read -r _rank p up cyc eol lat st; do
        printf 'WR-EOL: %s %s cycle=%s eol=%s latest=%s status=%s\n' "$p" "$up" "$cyc" "$eol" "$lat" "$st"
      done
else
  [ "$SRC_OK" -eq 1 ] && note "no EOL/outdated services detected among the tracked set"
fi
[ "$SRC_OK" -eq 1 ] || note "endoflife.date unavailable for one or more products — currency check degraded"
section end
