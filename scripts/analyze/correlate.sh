#!/usr/bin/env bash
# White Rabbit — cross-surface correlation. STRICTLY READ-ONLY (reads two local dumps).
#   scripts/analyze/correlate.sh <ssh_auth_dump> <web_access_dump>
# Intersects the attacker/actor IPs the two collectors already aggregated (server-side
# top-N lists) and flags IPs active on BOTH the SSH and HTTP surface — the signal a
# single-collector view cannot see. Emits a labeled section for the orchestrator's brain.
set -uo pipefail

SSH_DUMP="${1:-${WR_SSH_DUMP:-}}"
WEB_DUMP="${2:-${WR_WEB_DUMP:-}}"

section() { printf '\n===== WR-SECTION: %s =====\n' "$1"; }
note()    { printf 'WR-NOTE: %s\n' "$1"; }

for f in "$SSH_DUMP" "$WEB_DUMP"; do
  if [ -z "$f" ] || [ ! -r "$f" ]; then
    section cross_correlation
    note "input dump not readable or missing: '${f:-<empty>}' — cannot correlate"
    section end
    exit 1
  fi
done

# Emit the unique IPs from ONE FIXED COLUMN of each line inside a named WR-SECTION.
# Extracting a known column (not "any dotted-quad on the line") is essential: several sections
# carry attacker-controlled text — the request PATH in sensitive_path_hits/login_bruteforce, the
# UA in suspicious_user_agents, the Host/Referer value in suspicious_headers — so a whole-line
# scan would let a crafted request (e.g. GET /.env?x=203.0.113.5) inject a phantom IP and
# fabricate a cross-surface finding. The column value is then validated as IPv4 OR IPv6 (the SSH
# collector captures both), which also drops "-" placeholders and reverse-DNS PTR hostnames.
col_ips() {
  # $1 dump file, $2 section name, $3 awk field (a number, or the literal "NF" for the last field)
  awk -v want="$2" -v fld="$3" '
    /^===== WR-SECTION:/ { insec = ($0 ~ ("WR-SECTION: " want " ")) ? 1 : 0; next }
    insec { n = (fld=="NF") ? NF : fld+0; if (n>=1 && n<=NF) print $n }
  ' "$1" 2>/dev/null \
    | grep -aE '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)$' | sort -u
}
has() { printf '%s\n' "$1" | grep -qxF "$2"; }

# Column map (see each collector's section comment):
#   top_failed_sources  "<cnt> <ip> <ptr>"                 -> field 2
#   accepted_logins     "<count> <user> <ip> <method>"     -> field 3 (deduped format; ip is 3rd)
#   top_client_ips      "<count> <ip> <err%>"              -> field 2
#   top_scanning_sources"<cnt4xx> <distinct> <ip>"         -> field 3
#   sensitive_path_hits "<count> <status> <path> <ip>"     -> last field (path is field 3)
#   login_bruteforce    "<count> <ip> <path> <fail>"       -> field 2
#   path_payloads       "<count> <ip> <status> <path>"     -> field 2
#   suspicious_user_agents "<count> <ua…> <sample_ip>"     -> last field (ua may contain spaces)
#   suspicious_headers  "<count> <kind> <value…> <ip>"     -> last field (value may contain spaces)
ssh_failed="$(col_ips "$SSH_DUMP" top_failed_sources 2)"
ssh_accepted="$(col_ips "$SSH_DUMP" accepted_logins 3)"
web_client="$(col_ips "$WEB_DUMP" top_client_ips 2)"
web_scanner="$(col_ips "$WEB_DUMP" top_scanning_sources 3)"
web_sensitive="$(col_ips "$WEB_DUMP" sensitive_path_hits NF)"
web_loginbf="$(col_ips "$WEB_DUMP" login_bruteforce 2)"
web_payload="$(col_ips "$WEB_DUMP" path_payloads 2)"
web_ua="$(col_ips "$WEB_DUMP" suspicious_user_agents NF)"
web_header="$(col_ips "$WEB_DUMP" suspicious_headers NF)"

all_ssh="$(printf '%s\n%s\n' "$ssh_failed" "$ssh_accepted" | grep -a . | sort -u)"
all_web="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$web_client" "$web_scanner" "$web_sensitive" "$web_loginbf" "$web_payload" "$web_ua" "$web_header" | grep -a . | sort -u)"
common="$(comm -12 <(printf '%s\n' "$all_ssh") <(printf '%s\n' "$all_web") | grep -a . )"

section cross_correlation
if [ -z "$common" ]; then
  note "no IP appears in both the SSH and web dumps — no cross-surface actor detected"
else
  printf '%s\n' "$common" | while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    sroles=""; has "$ssh_failed" "$ip"   && sroles="${sroles}failed,"
               has "$ssh_accepted" "$ip" && sroles="${sroles}accepted,"
    wroles=""; has "$web_client" "$ip"    && wroles="${wroles}client,"
               has "$web_scanner" "$ip"   && wroles="${wroles}scanner,"
               has "$web_sensitive" "$ip" && wroles="${wroles}sensitive,"
               has "$web_loginbf" "$ip"   && wroles="${wroles}login-bf,"
               has "$web_payload" "$ip"   && wroles="${wroles}payload,"
               has "$web_ua" "$ip"        && wroles="${wroles}ua,"
               has "$web_header" "$ip"    && wroles="${wroles}header,"
    sroles="${sroles%,}"; wroles="${wroles%,}"
    # Severity: an accepted SSH login means a foothold — any web activity from that same IP is
    # critical. An SSH brute-forcer that also actively attacks the web (scan / login-bf / sensitive
    # probe / scanner-UA / header manipulation) is a coordinated attacker (high). Otherwise the
    # shared presence (e.g. just a busy client) is notable but softer (medium).
    case "$sroles" in
      *accepted*) sev=critical ;;
      *) case "$wroles" in *scanner*|*login-bf*|*sensitive*|*payload*|*ua*|*header*) sev=high ;; *) sev=medium ;; esac ;;
    esac
    printf 'WR-CROSS: %s ssh=%s web=%s severity=%s\n' "$ip" "$sroles" "$wroles" "$sev"
  done
fi
section end
note "correlation complete"
