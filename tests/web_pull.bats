#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/collect/web_pull.sh"
NGINX_FIXTURE="${BATS_TEST_DIRNAME}/fixtures/web-nginx-sample.log"
CADDY_FIXTURE="${BATS_TEST_DIRNAME}/fixtures/web-caddy-sample.json"

run_web() {
  run env WR_WEB_SOURCE="$NGINX_FIXTURE" bash "$SCRIPT"
}

run_web_caddy() {
  run env WR_WEB_SOURCE="$CADDY_FIXTURE" WR_WEB_FORMAT=auto bash "$SCRIPT"
}

@test "emits all 12 section markers, exit 0 (nginx fixture)" {
  run_web
  [ "$status" -eq 0 ]
  local s
  for s in meta top_client_ips sensitive_path_hits top_scanning_sources status_daily \
           login_bruteforce path_payloads notable_5xx suspicious_user_agents suspicious_headers evidence end; do
    echo "$output" | grep -q "WR-SECTION: $s" || { echo "missing section: $s"; return 1; }
  done
}

@test "path_payloads flags a directory-traversal request in the URL path (nginx)" {
  run_web
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: path_payloads/{f=1;next} /WR-SECTION:/{f=0} f')"
  # fixture line: GET /../../etc/passwd -> 400 from 203.0.113.60
  echo "$sec" | grep -qE '203\.0\.113\.60 400 /\.\./\.\./etc/passwd' || { echo "got: $sec"; return 1; }
}

@test "path_payloads does NOT flag a benign path (no false positive)" {
  run_web
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: path_payloads/{f=1;next} /WR-SECTION:/{f=0} f')"
  # a normal API path must never appear (guards the mawk '\.'->'.' over-match regression)
  ! echo "$sec" | grep -qE '/api/|/index\.html|/static/' || { echo "benign path flagged as payload: $sec"; return 1; }
}

@test "awk-bound regexes use POSIX [.] not backslash-dot (mawk portability)" {
  # mawk (Ubuntu's default awk) treats \. as a plain '.' (any char) and warns; a literal dot
  # in an awk-compiled regex must be written [.]. Real-run bug: \.\./ degraded to 'any-any-/'
  # and matched almost every URL. Guard every RE var that is passed to awk.
  local v
  for v in SENSITIVE_RE LOGIN_RE PAYLOAD_RE; do
    if grep -E "^$v=" "$SCRIPT" | grep -q '\\\.'; then
      echo "$v contains \\. — use [.] for a literal dot (mawk portability)"; return 1
    fi
  done
}

@test "meta reports the real source (not 'none') when logs are read" {
  run_web
  echo "$output" | awk '/WR-SECTION: meta/{f=1;next} /WR-SECTION:/{f=0} f' \
    | grep -qE '^source: file:' || { echo "meta source not set correctly: $(echo "$output" | grep '^source:')"; return 1; }
}

@test "sensitive_path_hits contains the critical 200 /.env exposure (nginx)" {
  run_web
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: sensitive_path_hits/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -qE '200 /\.env' || { echo "got: $sec"; return 1; }
}

@test "top_scanning_sources ranks the 6-path scanner IP first" {
  run_web
  local line
  line="$(echo "$output" | awk '/WR-SECTION: top_scanning_sources/{f=1;next} /WR-SECTION:/{f=0} f && NF' | head -1)"
  echo "$line" | grep -qE '^6 6 198\.51\.100\.20' || { echo "got: $line"; return 1; }
}

@test "login_bruteforce catches the wp-login.php brute-force IP" {
  run_web
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: login_bruteforce/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -qE '^5 198\.51\.100\.30 /wp-login\.php 5$' || { echo "got: $sec"; return 1; }
}

@test "suspicious_user_agents contains sqlmap" {
  run_web
  echo "$output" | awk '/WR-SECTION: suspicious_user_agents/{f=1;next} /WR-SECTION:/{f=0} f' | grep -qi 'sqlmap'
}

@test "caddy JSON fixture (with jq): emits sections and flags 200 /.env" {
  command -v jq >/dev/null 2>&1 || skip "jq not installed on this runner"
  run_web_caddy
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-SECTION: meta'
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: sensitive_path_hits/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -qE '200 /\.env' || { echo "got: $sec"; return 1; }
}

@test "caddy JSON fixture degraded (jq forced off via WR_WEB_NO_JQ): still flags 200 /.env and notes jq absent" {
  run env WR_WEB_SOURCE="$CADDY_FIXTURE" WR_WEB_FORMAT=json WR_WEB_NO_JQ=1 bash "$SCRIPT"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-NOTE: jq absent'
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: sensitive_path_hits/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -qE '200 /\.env' || { echo "got: $sec"; return 1; }
}

@test "suspicious_headers flags the host-is-ip anomaly (caddy fixture)" {
  run_web_caddy
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: suspicious_headers/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -q 'host-is-ip' || { echo "got: $sec"; return 1; }
  echo "$sec" | grep -q '203\.0\.113\.99'
}

@test "meta caps input to WR_WEB_MAX_LINES most-recent lines and notes the truncation" {
  # Scalability guard: on a 1.3M-request host the collector must not hold every line in memory.
  # Cap at 10 over a 30-line source → only the last 10 are analyzed, and truncation is disclosed.
  BIG="$(mktemp)"
  for i in $(seq 1 30); do
    printf '203.0.113.%d - - [01/Jan/2025:00:00:00 +0000] "GET /p%d HTTP/1.1" 200 10 "-" "ua"\n' "$((i % 250))" "$i"
  done > "$BIG"
  run env WR_WEB_SOURCE="$BIG" WR_WEB_MAX_LINES=10 bash "$SCRIPT"
  [ "$status" -eq 0 ]
  local meta
  meta="$(echo "$output" | awk '/WR-SECTION: meta/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$meta" | grep -q 'total_requests: 10' || { echo "got meta: $meta"; return 1; }
  echo "$meta" | grep -qi 'capped' || { echo "no truncation note: $meta"; return 1; }
  # The cap keeps the most-recent lines (tail): the evidence tail shows p21+, never the oldest p1.
  echo "$output" | grep -qE '/p2[1-9] '
  ! echo "$output" | grep -qE '/p[1-9] '
  rm -f "$BIG"
}

@test "collector is read-only: no file-write redirects, no mutating commands in the body" {
  # Strip safe /dev/null + fd-dup redirects AND the '>=' numeric-comparison operator used inside
  # the awk aggregation pipelines (e.g. "$4+0>=400") — that is not a shell redirect — then assert
  # no bare '>' remains.
  local clean
  clean="$(grep -vE '^[[:space:]]*#' "$SCRIPT" | sed -E 's#[0-9]*>>?[[:space:]]*/dev/null##g; s#[0-9]*>&[0-9-]##g; s#>=#GE#g')"
  ! echo "$clean" | grep -q '>' || { echo "found a file-write redirect"; return 1; }
  # Same comment-stripped content ($clean) — a deny-word inside a doc-comment (e.g. 'dd' in a
  # '[dd/Mon/yyyy]' format note) is not a mutating command in the executable body.
  ! echo "$clean" | grep -qE '(\brm\b|\bmv\b|\btee\b|\bchmod\b|\bchown\b|\bkill\b|\bdd\b|systemctl[[:space:]]+(stop|start|restart)|ufw[[:space:]]+(enable|allow|deny)|iptables[[:space:]]+-[AD])' || { echo "found a mutating command"; return 1; }
}

@test "run_ro is only ever called with read-only commands (cat, zcat, docker)" {
  local bad
  bad="$(grep -oE 'run_ro [a-zA-Z_-]+' "$SCRIPT" | awk '{print $2}' | grep -vE '^(cat|zcat|docker)$' || true)"
  [ -z "$bad" ] || { echo "run_ro used with non-read command(s): $bad"; return 1; }
}

@test "every run_ro docker call is immediately followed by logs or ps" {
  local bad
  bad="$(grep -oE 'run_ro docker [a-z]+' "$SCRIPT" | awk '{print $3}' | grep -vE '^(logs|ps)$' || true)"
  [ -z "$bad" ] || { echo "run_ro docker used with non-allowed subcommand(s): $bad"; return 1; }
  grep -q 'run_ro docker ps' "$SCRIPT"
  grep -q 'run_ro docker logs' "$SCRIPT"
}
