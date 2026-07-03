#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/collect/log_pull.sh"
FIXTURE="${BATS_TEST_DIRNAME}/fixtures/auth-sample.log"

# Run the collector against the fixture, with a stub `dig` (no real DNS) for hermeticity.
run_collector() {
  STUB="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/dig"   # PTR lookups return nothing, fast
  chmod +x "$STUB/dig"
  run env PATH="$STUB:$PATH" WR_AUTH_SOURCE="$FIXTURE" bash "$SCRIPT"
  rm -rf "$STUB"
}

@test "emits all section markers, exit 0" {
  run_collector
  [ "$status" -eq 0 ]
  local s
  for s in meta top_failed_sources top_invalid_users accepted_logins daily_failed defenses evidence end; do
    echo "$output" | grep -q "WR-SECTION: $s" || { echo "missing section: $s"; return 1; }
  done
}

@test "top_failed_sources ranks the brute-force IP first with count 50" {
  run_collector
  # first data line of the section is the highest count
  local line
  line="$(echo "$output" | awk '/WR-SECTION: top_failed_sources/{f=1;next} /WR-SECTION:/{f=0} f && NF' | head -1)"
  echo "$line" | grep -qE '^50 203\.0\.113\.10' || { echo "got: $line"; return 1; }
}

@test "top_invalid_users lists probed usernames" {
  run_collector
  echo "$output" | awk '/WR-SECTION: top_invalid_users/{f=1;next} /WR-SECTION:/{f=0} f' | grep -q 'oracle'
  echo "$output" | awk '/WR-SECTION: top_invalid_users/{f=1;next} /WR-SECTION:/{f=0} f' | grep -q 'admin'
}

@test "accepted_logins includes the legit and the breach login" {
  run_collector
  local acc
  acc="$(echo "$output" | awk '/WR-SECTION: accepted_logins/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$acc" | grep -qE '^[0-9]+ hola 10\.0\.0\.5 publickey'
  echo "$acc" | grep -qE '^[0-9]+ deploy 203\.0\.113\.10 password'   # breach: accepted from the brute-force IP
}

@test "accepted_logins is deduped with an occurrence count, most frequent first" {
  run_collector
  local acc
  acc="$(echo "$output" | awk '/WR-SECTION: accepted_logins/{f=1;next} /WR-SECTION:/{f=0} f && NF' | grep -v '^WR-NOTE:')"
  # hola@10.0.0.5 publickey occurs 3x in the fixture -> a single line with count 3
  echo "$acc" | grep -qE '^3 hola 10\.0\.0\.5 publickey' || { echo "expected deduped count line; got: $acc"; return 1; }
  # deploy@203 occurs once -> count 1
  echo "$acc" | grep -qE '^1 deploy 203\.0\.113\.10 password' || { echo "missing single-count line; got: $acc"; return 1; }
  # sorted by count desc: the highest-count tuple is first
  echo "$acc" | head -1 | grep -qE '^3 ' || { echo "not sorted by count desc; first line: $(echo "$acc" | head -1)"; return 1; }
}

@test "top_failed_sources includes rhost= IPs from PAM auth-failure lines" {
  run_collector
  local sec
  sec="$(echo "$output" | awk '/WR-SECTION: top_failed_sources/{f=1;next} /WR-SECTION:/{f=0} f')"
  echo "$sec" | grep -qE '198\.51\.100\.9' || { echo "missing rhost= IP in top_failed_sources: $sec"; return 1; }
}

@test "accepted_logins is capped and notes truncation when over WR_ACCEPTED_MAX" {
  STUB="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/dig"
  chmod +x "$STUB/dig"
  run env PATH="$STUB:$PATH" WR_AUTH_SOURCE="$FIXTURE" WR_ACCEPTED_MAX=1 bash "$SCRIPT"
  rm -rf "$STUB"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-NOTE: accepted_logins truncated at 1 of 2 lines' || { echo "missing truncation note"; return 1; }
  local acc_count
  acc_count="$(echo "$output" | awk '/WR-SECTION: accepted_logins/{f=1;next} /WR-SECTION:/{f=0} f && NF' | grep -vc '^WR-NOTE:')"
  [ "$acc_count" -eq 1 ] || { echo "expected 1 accepted_logins data line, got $acc_count"; return 1; }
}

@test "top_failed_sources falls back gracefully when dig is absent (WR_NO_DIG)" {
  run env WR_AUTH_SOURCE="$FIXTURE" WR_NO_DIG=1 bash "$SCRIPT"
  [ "$status" -eq 0 ]
  # A note explains PTR was skipped...
  echo "$output" | grep -qiE 'dig.*(not present|absent|skipped)|PTR.*skipped' || { echo "missing dig-absent note"; return 1; }
  # ...and the section still ranks the brute-force IP, with '-' in the PTR column.
  local line
  line="$(echo "$output" | awk '/WR-SECTION: top_failed_sources/{f=1;next} /WR-SECTION:/{f=0} f && NF' | grep -v '^WR-NOTE:' | head -1)"
  echo "$line" | grep -qE '^50 203\.0\.113\.10 -$' || { echo "expected '<count> <ip> -' with PTR skipped; got: $line"; return 1; }
}

@test "collector is read-only: no file-write redirects, no mutating commands in the body" {
  # strip safe /dev/null + fd-dup redirects, then assert no '>' (file write) remains
  local clean
  clean="$(sed -E 's#[0-9]*>>?[[:space:]]*/dev/null##g; s#[0-9]*>&[0-9-]##g' "$SCRIPT")"
  ! echo "$clean" | grep -q '>' || { echo "found a file-write redirect"; return 1; }
  ! grep -qE '(\brm\b|\bmv\b|\btee\b|\bchmod\b|\bchown\b|\bkill\b|\bdd\b|systemctl[[:space:]]+(stop|start|restart)|ufw[[:space:]]+(enable|allow|deny)|iptables[[:space:]]+-[AD])' "$SCRIPT"
}

@test "run_ro is only ever called with read-only commands" {
  local bad
  bad="$(grep -oE 'run_ro [a-z-]+' "$SCRIPT" | awk '{print $2}' | grep -vE '^(journalctl|cat|zcat|dig|host)$' || true)"
  [ -z "$bad" ] || { echo "run_ro used with non-read command(s): $bad"; return 1; }
}
