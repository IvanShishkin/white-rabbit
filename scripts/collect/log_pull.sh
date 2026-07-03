#!/usr/bin/env bash
# White Rabbit — SSH/auth intrusion-hunt collector. STRICTLY READ-ONLY.
#   ssh user@host 'bash -s' < scripts/collect/log_pull.sh
# Aggregates server-side (read-only text tools) into a compact labeled dump.
set -uo pipefail

WR_COLLECTOR_VERSION=1
WR_DAYS="${WR_DAYS:-7}"
WR_TOPN="${WR_TOPN:-20}"
WR_ACCEPTED_MAX="${WR_ACCEPTED_MAX:-200}"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Run a READ-ONLY command, preferring passwordless sudo -n, else plain. Reads only.
run_ro() {
  if have sudo && sudo -n true 2>/dev/null; then sudo -n "$@" 2>/dev/null && return 0; fi
  "$@" 2>/dev/null
}

# Emit raw sshd auth lines from the best available source (test seam: WR_AUTH_SOURCE).
auth_lines() {
  if [ -n "${WR_AUTH_SOURCE:-}" ]; then
    case "$WR_AUTH_SOURCE" in
      *.gz) run_ro zcat "$WR_AUTH_SOURCE" ;;
      *)    run_ro cat  "$WR_AUTH_SOURCE" ;;
    esac
    return
  fi
  local j
  j="$(run_ro journalctl -u ssh -u sshd --since "-${WR_DAYS} days" --no-pager)"
  if [ -n "$j" ]; then printf '%s\n' "$j"; return; fi
  { run_ro cat /var/log/auth.log; [ -r /var/log/auth.log.1 ] && run_ro cat /var/log/auth.log.1; } | grep -a 'sshd'
}

LINES="$(auth_lines)"

section meta
printf 'WR-COLLECTOR-VERSION: %s\n' "$WR_COLLECTOR_VERSION"
if have hostname; then printf 'hostname: '; hostname 2>/dev/null; fi
printf 'window_days: %s\n' "$WR_DAYS"
printf 'source: %s\n' "${WR_AUTH_SOURCE:-journald-or-authlog}"
printf 'total_ssh_lines: %s\n' "$(printf '%s\n' "$LINES" | grep -ac . )"

# Reverse-DNS enrichment is optional: dig may not be installed on the host. Decide once,
# note it if unavailable, and emit '-' for the PTR column instead of spawning failing digs.
if [ -n "${WR_NO_DIG:-}" ] || ! have dig; then WR_DIG=0; else WR_DIG=1; fi
section top_failed_sources
[ "$WR_DIG" -eq 1 ] || note "dig not present — PTR (reverse-DNS) enrichment skipped; PTR column shows '-'"
printf '%s\n' "$LINES" | grep -aE 'Failed password|Invalid user|authentication failure' \
  | grep -aoE '(from |rhost=)[0-9a-fA-F:.]+' | sed -E 's/^(from |rhost=)//' | sort | uniq -c | sort -rn | head -"$WR_TOPN" \
  | while read -r cnt ip; do
      [ -n "$cnt" ] || continue
      ptr='-'
      [ "$WR_DIG" -eq 1 ] && ptr="$(run_ro dig +short -x "$ip" 2>/dev/null | head -1)"
      printf '%s %s %s\n' "$cnt" "$ip" "${ptr:--}"
    done

section top_invalid_users
printf '%s\n' "$LINES" | grep -aoE 'Invalid user [^ ]+' | awk '{print $3}' \
  | sort | uniq -c | sort -rn | head -"$WR_TOPN" | awk '{printf "%s %s\n",$1,$2}'

section accepted_logins
ACCEPTED="$(printf '%s\n' "$LINES" | grep -aE 'Accepted ' \
  | sed -E 's/.*Accepted ([^ ]+) for ([^ ]+) from ([^ ]+).*/\2 \3 \1/' \
  | sort | uniq -c | sort -rn | awk '{printf "%s %s %s %s\n",$1,$2,$3,$4}')"
ACCEPTED_TOTAL="$(printf '%s\n' "$ACCEPTED" | grep -ac .)"
if [ "$ACCEPTED_TOTAL" -gt 0 ]; then
  printf '%s\n' "$ACCEPTED" | head -"$WR_ACCEPTED_MAX"
  if [ "$ACCEPTED_TOTAL" -gt "$WR_ACCEPTED_MAX" ]; then
    note "accepted_logins truncated at $WR_ACCEPTED_MAX of $ACCEPTED_TOTAL lines"
  fi
fi

section daily_failed
printf '%s\n' "$LINES" | grep -aE 'Failed password|Invalid user|authentication failure' \
  | awk '{print $1" "$2}' | sort | uniq -c | awk '{printf "%s %s %s\n",$2,$3,$1}'

section defenses
if have fail2ban-client; then note "fail2ban: installed"; else note "fail2ban: NOT installed"; fi
if have cscli;           then note "crowdsec: installed"; else note "crowdsec: NOT installed"; fi

section evidence
printf '%s\n' "$LINES" | grep -aE 'Failed password' | head -2
printf '%s\n' "$LINES" | grep -aE 'Invalid user'    | head -2
printf '%s\n' "$LINES" | grep -aE 'Accepted '       | head -5

section end
note "log-hunt snapshot complete"
