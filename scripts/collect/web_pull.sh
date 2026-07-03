#!/usr/bin/env bash
# White Rabbit — HTTP access-log intrusion-hunt collector. STRICTLY READ-ONLY.
#   ssh user@host 'bash -s' < scripts/collect/web_pull.sh
# Reads nginx (combined) or Caddy (JSON) access logs, normalizes to a TAB-separated
# 8-field contract, aggregates server-side (read-only text tools) into a labeled dump.
set -uo pipefail

WR_COLLECTOR_VERSION=1
WR_DAYS="${WR_DAYS:-7}"
WR_TOPN="${WR_TOPN:-20}"
WR_WEB_FORMAT="${WR_WEB_FORMAT:-auto}"
WR_WEB_HOST="${WR_WEB_HOST:-}"
WR_WEB_MAX_LINES="${WR_WEB_MAX_LINES:-200000}"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Cap the raw stream to the most-recent WR_WEB_MAX_LINES lines (0/empty = no cap). Streaming
# `tail` buffers only that many lines, so a 1.3M-request host never materializes every log line
# in a shell variable — that unbounded RAW/TSV was the memory blow-up that tore SSH sessions
# (exit 255). Sources are emitted oldest-first below so the cap keeps the freshest entries.
_cap() { if [ "${WR_WEB_MAX_LINES:-0}" -gt 0 ] 2>/dev/null; then tail -n "$WR_WEB_MAX_LINES"; else cat; fi; }

# Run a READ-ONLY command, preferring passwordless sudo -n, else plain. Reads only.
run_ro() {
  if have sudo && sudo -n true 2>/dev/null; then sudo -n "$@" 2>/dev/null && return 0; fi
  "$@" 2>/dev/null
}

# --- Pattern lists (documented, matched against the normalized path/ua/referer) ---
# NOTE: use POSIX bracket `[.]` for a literal dot, NEVER `\.`. These strings are compiled as
# regexes by awk, and mawk (Ubuntu's default awk) treats `\.` as a plain `.` (any char) AND warns
# — e.g. `\.\./` would degrade to "any-any-slash" and match almost every URL (massive false
# positives in path_payloads / referer-payload). `[.]` is a literal dot in both mawk and gawk.
SENSITIVE_RE='(/[.]env|/[.]git|/[.]aws|/[.]ssh|/wp-config|/config[.]php|/[.]htpasswd|[.]sql([?]|$)|[.]bak([?]|$)|/phpinfo|/server-status)'
LOGIN_RE='(/wp-login[.]php|/login|/administrator|/admin|/user/login|/api/login|/signin)'
SCANNER_UA_RE='(sqlmap|nikto|nmap|masscan|wpscan|dirbuster|gobuster|nuclei|acunetix|zgrab|python-requests|Go-http-client|curl/|Wget/|libwww|okhttp)'
PAYLOAD_RE='([.][.]/|%2e%2e|union[[:space:]]+select|<script|/etc/passwd|[$][{]jndi:|base64_decode)'

SOURCE_DESC="none"
FORMAT="none"

# Emit raw log lines from the best available source. The FIRST line is a `WR-SRC:<desc>` marker
# naming the source; the parent strips it and uses it for SOURCE_DESC. (A plain `SOURCE_DESC=...`
# set in here would be lost: raw_lines runs inside the `RAW="$(...)"` command-substitution
# subshell, so any variable it assigns never reaches the parent — that is why meta once printed
# `source: none` even after reading 1.3M lines.) Test seam: WR_WEB_SOURCE.
raw_lines() {
  local out f cont
  if [ -n "${WR_WEB_SOURCE:-}" ]; then
    printf 'WR-SRC:file:%s\n' "$WR_WEB_SOURCE"
    case "$WR_WEB_SOURCE" in
      *.gz) run_ro zcat "$WR_WEB_SOURCE" | _cap ;;
      *)    run_ro cat  "$WR_WEB_SOURCE" | _cap ;;
    esac
    return
  fi
  # Emit oldest-first (rotated .gz, then .1, then the live access.log LAST) so `| _cap`'s tail
  # keeps the most-recent lines rather than the oldest rotated ones.
  out="$( { for f in /var/log/nginx/access.log.*.gz; do [ -e "$f" ] && run_ro zcat "$f"; done; \
            run_ro cat /var/log/nginx/access.log.1; run_ro cat /var/log/nginx/access.log; } 2>/dev/null | _cap )"
  if [ -n "$out" ]; then printf 'WR-SRC:nginx:/var/log/nginx\n'; printf '%s\n' "$out"; return; fi
  out="$( for f in /var/log/caddy/*.log; do [ -e "$f" ] && run_ro cat "$f"; done 2>/dev/null | _cap )"
  if [ -n "$out" ]; then printf 'WR-SRC:caddy:/var/log/caddy\n'; printf '%s\n' "$out"; return; fi
  if have docker; then
    cont="${WR_WEB_CONTAINER:-}"
    [ -z "$cont" ] && cont="$(run_ro docker ps --format '{{.Names}}' | grep -iE 'caddy|nginx' | head -1)"
    if [ -n "$cont" ]; then printf 'WR-SRC:docker:%s\n' "$cont"; run_ro docker logs "$cont" --tail "$WR_WEB_MAX_LINES"; return; fi
  fi
}

RAWFULL="$(raw_lines)"
case "$RAWFULL" in
  WR-SRC:*) SOURCE_DESC="$(printf '%s\n' "$RAWFULL" | head -1 | sed 's/^WR-SRC://')"
            RAW="$(printf '%s\n' "$RAWFULL" | tail -n +2)" ;;
  *)        RAW="$RAWFULL" ;;
esac
unset RAWFULL

detect_format() {
  case "$WR_WEB_FORMAT" in json|combined) printf '%s' "$WR_WEB_FORMAT"; return ;; esac
  local first
  first="$(printf '%s\n' "$RAW" | grep -avE '^[[:space:]]*$' | head -1)"
  case "$first" in '{'*) printf 'json' ;; *) printf 'combined' ;; esac
}
[ -n "$RAW" ] && FORMAT="$(detect_format)"

# Portable per-field JSON extractor: always emits one line per input line (default "-").
# NOTE: the `t`/catch-all chain is joined with actual newlines, not `;` — BSD/macOS sed (unlike
# GNU sed) requires `t` to be terminated by a newline, not a semicolon, or it misparses the rest
# of the script as the branch's label ("undefined label" error). Newlines work on both.
_jf() { printf '%s\n' "$RAW" | sed -E "$1
t
s/.*/-/"; }

JQ_NOTE=""
# Decide this BEFORE the TSV="$(normalize)" command substitution below: normalize() runs inside
# a subshell (command substitution always forks one), so an assignment made *inside* it is lost
# the instant that subshell exits — it can never reach this JQ_NOTE variable in the parent shell.
# Deciding it here, in the parent shell, is what makes the "WR-NOTE: jq absent" note actually appear.
if [ "$FORMAT" = "json" ] && { ! have jq || [ -n "${WR_WEB_NO_JQ:-}" ]; }; then
  JQ_NOTE="jq absent — degraded JSON parse (reduced fidelity)"
fi
# Normalize RAW to TSV: ip \t method \t path \t status \t bytes \t ua \t referer \t host
normalize() {
  case "$FORMAT" in
    combined)
      printf '%s\n' "$RAW" \
        | sed -E 's/^([^ ]+) [^ ]+ [^ ]+ \[[^]]*\] "([A-Z]+) ([^ "]+)[^"]*" ([0-9]{3}) ([0-9-]+) "([^"]*)" "([^"]*)".*/\1\t\2\t\3\t\4\t\5\t\7\t\6\t-/' \
        | awk -F'\t' 'NF>=8'
      ;;
    json)
      if have jq && [ -z "${WR_WEB_NO_JQ:-}" ]; then
        printf '%s\n' "$RAW" | jq -rc '[(.request.remote_ip // .request.client_ip // "-"), (.request.method // "-"), (.request.uri // "-"), ((.status // "-")|tostring), ((.size // "-")|tostring), (.request.headers."User-Agent"[0] // "-"), (.request.headers.Referer[0] // "-"), (.request.host // "-")] | @tsv' 2>/dev/null
      else
        paste -d '\t' \
          <(_jf 's/.*"remote_ip":"([^"]*)".*/\1/
t
s/.*"client_ip":"([^"]*)".*/\1/') \
          <(_jf 's/.*"method":"([^"]*)".*/\1/') \
          <(_jf 's/.*"uri":"([^"]*)".*/\1/') \
          <(_jf 's/.*"status":([0-9]+).*/\1/') \
          <(_jf 's/.*"size":([0-9]+).*/\1/') \
          <(_jf 's/.*"User-Agent":\["([^"]*)".*/\1/') \
          <(_jf 's/.*"Referer":\["([^"]*)".*/\1/') \
          <(_jf 's/.*"host":"([^"]*)".*/\1/') \
          | awk -F'\t' '!($1=="-" && $3=="-")'
      fi
      ;;
  esac
}
TSV="$(normalize)"
TOTAL="$(printf '%s\n' "$TSV" | grep -ac .)"

section meta
printf 'WR-COLLECTOR-VERSION: %s\n' "$WR_COLLECTOR_VERSION"
printf 'source: %s\n' "$SOURCE_DESC"
printf 'format: %s\n' "$FORMAT"
printf 'window_days: %s\n' "$WR_DAYS"
printf 'total_requests: %s\n' "$TOTAL"
# Disclose truncation: if the raw input reached the cap, older entries were not analyzed. Silent
# truncation would read as "full history covered" when it was not.
RAW_COUNT="$(printf '%s\n' "$RAW" | grep -ac .)"
if [ "${WR_WEB_MAX_LINES:-0}" -gt 0 ] 2>/dev/null && [ "$RAW_COUNT" -ge "$WR_WEB_MAX_LINES" ]; then
  note "input capped to the most-recent $WR_WEB_MAX_LINES lines (WR_WEB_MAX_LINES) — older entries were NOT analyzed; raise WR_WEB_MAX_LINES for full history"
fi
[ -n "$JQ_NOTE" ] && note "$JQ_NOTE"
if [ "$TOTAL" -eq 0 ]; then note "no web access logs found (set WR_WEB_SOURCE / WR_WEB_CONTAINER or enable file logging)"; fi

section top_client_ips
# <count> <ip> <err_ratio%>  — err = status >= 400
printf '%s\n' "$TSV" | awk -F'\t' 'NF>=8{t[$1]++; if($4+0>=400)e[$1]++} END{for(i in t) printf "%d %s %d\n", t[i], i, (e[i]*100/t[i])}' \
  | sort -rn | head -"$WR_TOPN" | awk '{printf "%s %s %s%%\n",$1,$2,$3}'

section sensitive_path_hits
# <count> <status> <path> <ip>  — requests to sensitive paths (status matters: 2xx = exposure)
printf '%s\n' "$TSV" | awk -F'\t' -v re="$SENSITIVE_RE" 'NF>=8 && $3 ~ re {printf "%s\t%s\t%s\n",$4,$3,$1}' \
  | sort | uniq -c | sort -rn | head -"$WR_TOPN" | awk -F'\t' '{n=$1; sub(/^[ \t]*[0-9]+ /,"",$1); printf "%s %s %s %s\n",n+0,$1,$2,$3}'

section top_scanning_sources
# <count_4xx> <distinct_paths> <ip>  — many 404/403 across many paths = scanner
printf '%s\n' "$TSV" | awk -F'\t' '$4+0>=400 && $4+0<500 {c[$1]++; k=$1 SUBSEP $3; if(!(k in seen)){seen[k]=1; d[$1]++}} END{for(i in c) printf "%d %d %s\n", c[i], d[i], i}' \
  | sort -rn | head -"$WR_TOPN"

section status_daily
# <date> <2xx> <3xx> <4xx> <5xx>  — date from the request line; combined has [dd/Mon/yyyy], json has ts — use evidence for exact times, bucket here by class only if date unavailable
printf '%s\n' "$RAW" | awk 'match($0,/\[[0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}/){d=substr($0,RSTART+1,11)} match($0,/"status":[0-9]+/){} {print}' >/dev/null 2>&1
printf '%s\n' "$TSV" | awk -F'\t' 'NF>=8{c=int($4/100); tot[c]++} END{printf "all 2xx=%d 3xx=%d 4xx=%d 5xx=%d\n", tot[2],tot[3],tot[4],tot[5]}'

section login_bruteforce
# <count> <ip> <path> <fail_count>  — POST to login endpoints; fail = 401/403
printf '%s\n' "$TSV" | awk -F'\t' -v re="$LOGIN_RE" 'NF>=8 && $2=="POST" && $3 ~ re {t[$1 SUBSEP $3]++; if($4==401||$4==403)f[$1 SUBSEP $3]++} END{for(k in t){split(k,a,SUBSEP); printf "%d %s %s %d\n", t[k], a[1], a[2], f[k]}}' \
  | sort -rn | head -"$WR_TOPN"

section path_payloads
# <count> <ip> <status> <path>  — attack payloads in the request PATH itself: directory traversal
# (../, %2e%2e), SQLi (union select), XSS (<script), local-file (/etc/passwd), Log4Shell (${jndi:),
# base64_decode. This is the dedicated path scan the web-log catalog previously said to eyeball;
# the same PAYLOAD_RE is now applied to the URL path, not only to Referer/Host. Status matters:
# a 2xx on a payload path may be a successful exploit, a 4xx a blocked/failed probe.
printf '%s\n' "$TSV" | awk -F'\t' -v pl="$PAYLOAD_RE" 'NF>=8 && $3 ~ pl {c[$1 SUBSEP $4 SUBSEP $3]++} END{for(k in c){split(k,a,SUBSEP); printf "%d %s %s %s\n", c[k], a[1], a[2], a[3]}}' \
  | sort -rn | head -"$WR_TOPN"

section notable_5xx
printf '%s\n' "$TSV" | awk -F'\t' '$4+0>=500 && $4+0<600 {c[$3]++} END{for(p in c) printf "%d %s\n", c[p], p}' \
  | sort -rn | head -"$WR_TOPN"

section suspicious_user_agents
# <count> <ua> <sample_ip>  — scanner/scripting/empty/payload UAs
printf '%s\n' "$TSV" | awk -F'\t' -v re="$SCANNER_UA_RE" -v pl="$PAYLOAD_RE" 'NF>=8 && ($6=="-"||$6==""||length($6)<8||$6 ~ re||$6 ~ pl){c[$6]++; ip[$6]=$1} END{for(u in c) printf "%d\t%s\t%s\n", c[u], u, ip[u]}' \
  | sort -rn | head -"$WR_TOPN" | awk -F'\t' '{printf "%s %s %s\n",$1,$2,$3}'

section suspicious_headers
# <count> <kind> <value> <ip>  — host anomaly / payload in referer/host / XFF spoof (within logged fields)
# NOTE: the awk variable holding WR_WEB_HOST is named `hexp`, NOT `exp` — `exp` collides with
# awk's built-in exp() math function. Using `-v exp=...` silently breaks string comparisons against
# it (e.g. `exp!=""` can evaluate true even when the value is empty), which would defeat the
# documented "empty WR_WEB_HOST → host-mismatch check is soft/skipped" behavior. `hexp` avoids it.
if [ "$FORMAT" = combined ]; then note "host/xff not in nginx combined format (only referer/ua available)"; fi
printf '%s\n' "$TSV" | awk -F'\t' -v hexp="$WR_WEB_HOST" -v pl="$PAYLOAD_RE" '
  NF>=8 {
    if ($8!="-" && $8!="" && hexp!="" && $8!=hexp) {k="host-mismatch\t" $8; c[k]++; ip[k]=$1}
    if ($8 ~ /^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/) {k="host-is-ip\t" $8; c[k]++; ip[k]=$1}
    if ($7 ~ pl) {k="referer-payload\t" $7; c[k]++; ip[k]=$1}
    if ($8 ~ pl) {k="host-payload\t" $8; c[k]++; ip[k]=$1}
  } END{for(k in c) printf "%d\t%s\t%s\n", c[k], k, ip[k]}' \
  | sort -rn | head -"$WR_TOPN" | awk -F'\t' '{printf "%s %s %s %s\n",$1,$2,$3,$4}'

section evidence
printf '%s\n' "$TSV" | awk -F'\t' -v re="$SENSITIVE_RE" '$3 ~ re {printf "%s %s %s %s\n",$1,$4,$2,$3}' | head -5
printf '%s\n' "$RAW" | head -3

section end
note "web-log-hunt snapshot complete"
