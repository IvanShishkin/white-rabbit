# Reporting v2 — Phase 1 Implementation Plan (bundle + findings.json + methodology)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move White Rabbit reports into self-contained per-run directory bundles, add a machine-checkable `findings.json` sidecar with a validator, and add a "Methodology / How to reproduce" section to every report.

**Architecture:** A new read-only analyzer `scripts/report/validate_findings.sh` (jq, stdout-only, guard-allowlisted) validates the sidecar's schema and its agreement with the report's severity counts. The audit skills are edited to write a directory bundle instead of flat files, to emit `findings.json` next to `report.md`, and to include a Methodology section. The existing 2026-07-10 report is migrated into a bundle as the end-to-end proof.

**Tech Stack:** bash + jq (jq is already a hard dependency of `hooks/guard.sh`), bats for tests. No network, no new dependencies.

## Global Constraints

- **Read-only posture.** New scripts read files and print to stdout only; they never write files, never mutate a host. (Verified by the "read-only by construction" grep test used for `cve_scan.sh`.)
- **jq only.** No `yq` / no new binaries. The sidecar is JSON, not YAML.
- **Bundle directory naming:** `reports/<YYYY-MM-DD>-<host>-<kind>/`, `kind ∈ {full,server,logs,web,cve}`. Stable filenames inside: `report.md`, `findings.json`, `snapshot.txt`, `logs.txt`, `web.txt`, `cve.txt`, `correlate.txt`.
- **findings.json schema (per element):** `id` (stable `<area>-<kebab>` slug), `severity` ∈ {critical,high,medium,low,info}, `area` ∈ {ssh,firewall,ports,access,persistence,patching,sysctl,docker,auth-log,web,cross,cve}, `title`, `evidence` (array of strings), `why`, `fix`, `mitre` (string or null), `status` ∈ {new,unchanged,resolved}. Top level: `target`, `host`, `collected`, `os`, `posture{read_only,hook_enforced}`, `surfaces{...}`, `summary{critical,high,medium,low,info}`, `findings[]`.
- **Files are saved with the file-write tool, never a shell redirect** (guard blocks `>`); this applies to the model authoring `report.md`/`findings.json`, unchanged from today.
- **Reports stay gitignored** (`reports/` is in `.gitignore`); only `scripts/`, `tests/`, `docs/`, `hooks/`, and skill files are committed.

---

### Task 1: `validate_findings.sh` + guard allowlist + tests

**Files:**
- Create: `scripts/report/validate_findings.sh`
- Create: `tests/fixtures/report/findings-valid.json`
- Create: `tests/validate_findings.bats`
- Modify: `hooks/guard.sh` (add the canonical-path allow entry, mirroring `WR_CVE_SCANNER`)

**Interfaces:**
- Produces: `scripts/report/validate_findings.sh <findings.json>` → prints `WR-VALIDATE: OK (<n> findings)` and exits 0 when valid; prints `WR-VALIDATE: FAIL` plus one `WR-VALIDATE: <error>` line per problem and exits 1 when invalid; exits 2 on unreadable input / missing jq.

- [ ] **Step 1: Write the fixture (a valid sidecar)**

Create `tests/fixtures/report/findings-valid.json`:

```json
{
  "target": "10.0.0.1",
  "host": "testbox",
  "collected": "2026-07-11",
  "os": "Ubuntu 24.04 LTS",
  "posture": { "read_only": true, "hook_enforced": true },
  "surfaces": { "server": "ok", "ssh_logs": "not_collected", "web_logs": "not_collected", "cve": "ok" },
  "summary": { "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0 },
  "findings": [
    { "id": "patching-eol", "severity": "critical", "area": "patching",
      "title": "EOL release", "evidence": ["PRETTY_NAME=..."], "why": "no patches",
      "fix": "upgrade", "mitre": null, "status": "new" },
    { "id": "ssh-root-login", "severity": "medium", "area": "ssh",
      "title": "root login by key", "evidence": ["permitrootlogin without-password"],
      "why": "bypasses sudo trail", "fix": "PermitRootLogin no", "mitre": null, "status": "new" }
  ]
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/validate_findings.bats`:

```bash
#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/report/validate_findings.sh"
GUARD="${BATS_TEST_DIRNAME}/../hooks/guard.sh"
FIX="${BATS_TEST_DIRNAME}/fixtures/report/findings-valid.json"
export WR_POLICY_DIR="${BATS_TEST_DIRNAME}/../policy"

setup() { TMP="$(mktemp -d)"; }
teardown() { [ -n "${TMP:-}" ] && rm -rf "$TMP" || true; }

guard_decision() {
  local out
  out="$(jq -n --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$GUARD")"
  if echo "$out" | grep -q '"deny"'; then echo deny; else echo allow; fi
}

@test "a well-formed findings.json validates" {
  run bash "$SCRIPT" "$FIX"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q 'WR-VALIDATE: OK (2 findings)'
}

@test "a missing required finding key fails" {
  jq 'del(.findings[0].fix)' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'finding\[0\] missing key: fix'
}

@test "a bad severity enum fails" {
  jq '.findings[0].severity = "showstopper"' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'bad severity: showstopper'
}

@test "a summary count that disagrees with the findings array fails" {
  jq '.summary.critical = 5' "$FIX" > "$TMP/f.json"
  run bash "$SCRIPT" "$TMP/f.json"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q 'summary.critical=5 but findings has 1'
}

@test "an unreadable input exits 2, not 0" {
  run bash "$SCRIPT" "/no/such/file.json"
  [ "$status" -eq 2 ]
}

@test "validator is read-only by construction (no writes, no mutators)" {
  ! grep -qE '>[[:space:]]*[^&/[:space:]]' "$SCRIPT"
  ! grep -qE '(^|[^[:alnum:]_.-])(rm|mv|cp|dd|tee|chmod|chown|truncate|mktemp|sed[[:space:]]+-i)([[:space:]]|$)' "$SCRIPT"
}

@test "validator is allowed by its canonical path but not by a planted same-named file" {
  [ "$(guard_decision "scripts/report/validate_findings.sh reports/x/findings.json")" = "allow" ]
  [ "$(guard_decision "/tmp/evil/validate_findings.sh a")" = "deny" ]
  [ "$(guard_decision "validate_findings.sh a")" = "deny" ]
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `bats tests/validate_findings.bats`
Expected: all FAIL — script does not exist yet (and the guard tests fail until the allowlist entry is added).

- [ ] **Step 4: Write `scripts/report/validate_findings.sh`**

```bash
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
```

Then `chmod +x scripts/report/validate_findings.sh`.

- [ ] **Step 5: Add the guard canonical-path allow entry**

In `hooks/guard.sh`, next to the existing `WR_CVE_SCANNER` definition (~line 19), add:

```bash
WR_VALIDATE_FINDINGS="${WR_ROOT_DIR}/scripts/report/validate_findings.sh"
```

and extend the allow `case` (~line 91) to include it:

```bash
      case "$canon" in
        "$WR_CORRELATOR"|"$WR_CVE_SCANNER"|"$WR_EXT_LIST"|"$WR_VALIDATE_FINDINGS") continue ;;
      esac
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `bats tests/validate_findings.bats`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/report/validate_findings.sh tests/validate_findings.bats tests/fixtures/report/findings-valid.json hooks/guard.sh
git commit -m "feat(report): findings.json validator + guard allowlist"
```

---

### Task 2: Bundle paths + findings.json contract + Methodology section in the skills

**Files:**
- Modify: `skills/wr-orchestrate/SKILL.md` (collector paths lines ~30-32, correlate ~44, cve ~57, delta glob ~79, report save ~111)
- Modify: `skills/wr-server-audit/SKILL.md:37,93`
- Modify: `skills/wr-log-hunt/SKILL.md:29,59`
- Modify: `skills/wr-web-hunt/SKILL.md:54,87`
- Modify: `skills/wr-cve/SKILL.md:30,35,42,60`
- Modify: `commands/wr.md` (delta-glob mention in routing, if present)

**Interfaces:**
- Consumes: the bundle naming rule and `findings.json` schema from Global Constraints.
- Produces: skill instructions that make the model write `reports/<DATE>-<host>-<kind>/{report.md,findings.json}` plus stable-named raw dumps, and a Methodology section in each report.

- [ ] **Step 1: Add a shared "Output bundle" rule to each skill's hard-rules block**

In every one of the five skill files, add this bullet to the "Hard rules" list (adjust `<kind>` per skill: `full` for wr-orchestrate, `server`, `logs`, `web`, `cve`):

```markdown
- **Output goes in one bundle directory:** create `reports/<YYYY-MM-DD>-<host>-<kind>/` and write
  every artifact there with stable names — `report.md`, `findings.json`, and the raw dumps
  (`snapshot.txt`, `logs.txt`, `web.txt`, `cve.txt`, `correlate.txt` as applicable). Use the
  file-write tool, never a shell redirect.
```

- [ ] **Step 2: Rewrite the raw-dump and report save paths to the bundle**

Apply these exact replacements (old → new):

- `skills/wr-orchestrate/SKILL.md`:
  - `reports/snapshot-<host>-<DATE>.txt` → `reports/<DATE>-<host>-full/snapshot.txt`
  - `reports/logs-raw-<host>-<DATE>.txt` → `reports/<DATE>-<host>-full/logs.txt`
  - `reports/web-raw-<host>-<DATE>.txt` → `reports/<DATE>-<host>-full/web.txt`
  - correlate args and cve arg: same three new paths
  - delta glob `reports/full-<host>-*.md` → `reports/*-<host>-full/report.md`
  - final save `reports/full-<host>-<YYYY-MM-DD>.md` → `reports/<DATE>-<host>-full/report.md`
- `skills/wr-server-audit/SKILL.md`: `reports/snapshot-<host>-<YYYY-MM-DD>.txt` → `reports/<DATE>-<host>-server/snapshot.txt`; `reports/server-<host>-<YYYY-MM-DD>.md` → `reports/<DATE>-<host>-server/report.md`
- `skills/wr-log-hunt/SKILL.md`: `reports/logs-raw-<host>-<YYYY-MM-DD>.txt` → `reports/<DATE>-<host>-logs/logs.txt`; `reports/logs-<host>-<YYYY-MM-DD>.md` → `reports/<DATE>-<host>-logs/report.md`
- `skills/wr-web-hunt/SKILL.md`: `reports/web-raw-<host>-<YYYY-MM-DD>.txt` → `reports/<DATE>-<host>-web/web.txt`; `reports/web-<host>-<YYYY-MM-DD>.md` → `reports/<DATE>-<host>-web/report.md`
- `skills/wr-cve/SKILL.md`: snapshot reuse/collect path → prefer `reports/<DATE>-<host>-full/snapshot.txt` or `reports/<DATE>-<host>-server/snapshot.txt` if either exists, else `reports/<DATE>-<host>-cve/snapshot.txt`; `cve_scan.sh <that path>`; report `reports/cve-<host>-<YYYY-MM-DD>.md` → `reports/<DATE>-<host>-cve/report.md`

- [ ] **Step 3: Add the findings.json emission instruction to each skill's Report step**

Append to the "Report" step of every skill (right after the "save report.md" line):

```markdown
- **Also emit `findings.json`** in the same bundle, from the same findings you just wrote — do
  not re-parse the prose. It is a JSON object with `target, host, collected, os,
  posture{read_only,hook_enforced}, surfaces{...}, summary{critical,high,medium,low,info}` and a
  `findings[]` array; each finding: `id` (stable `<area>-<kebab>` slug), `severity`, `area`,
  `title`, `evidence[]`, `why`, `fix`, `mitre` (or null), `status` (`new` on a first sweep).
  After writing it, run `scripts/report/validate_findings.sh reports/<DATE>-<host>-<kind>/findings.json`
  and fix any `WR-VALIDATE: FAIL` line before finishing. The `summary` counts MUST equal the
  per-severity tally of `findings[]`.
```

- [ ] **Step 4: Add the Methodology section to each report template**

In every skill's report template, insert this section immediately before `## Coverage` (or before the closing posture line where there is no Coverage section):

```markdown
## Methodology — how this was checked (and how to reproduce)

For each surface that ran, the exact command and what it reads:
- <the collector/analyzer command used>  → reads <what>, does not read <what>.
Re-verify any single finding from its quoted evidence, e.g.:
- SSH config: `ssh <target> 'sshd -T' | grep -i <directive>`
- listening ports: `ssh <target> 'ss -tulpn'`
- a CVE row: `scripts/analyze/cve_scan.sh <bundle>/snapshot.txt | grep <cve-id>`
State plainly which surfaces did NOT run and why (blocked, unreachable, unprivileged).
```

- [ ] **Step 5: Manual verification (no automated test — these are model instructions)**

Re-read each edited skill end-to-end. Confirm: (a) no remaining `reports/<kind>-<host>-<date>.<ext>` flat paths; (b) every skill names `findings.json` and the validator; (c) every report template has a Methodology section. Grep to confirm no flat paths remain:

Run: `grep -rnE 'reports/(snapshot|logs-raw|web-raw|full|server|logs|web|cve)-' skills/ commands/`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add skills/ commands/
git commit -m "feat(report): per-run bundle directories, findings.json emission, methodology section"
```

---

### Task 3: Migrate the 2026-07-10 report into a v2 bundle (end-to-end proof + cosmetic fixes)

**Files:**
- Create: `reports/2026-07-10-158.160.2.43-full/report.md` (moved + fixed from the current `reports/full-158.160.2.43-2026-07-10.md`)
- Create: `reports/2026-07-10-158.160.2.43-full/report.ru.md` (moved + fixed from the `.ru.md`)
- Create: `reports/2026-07-10-158.160.2.43-full/findings.json`
- Move: existing `snapshot-...txt`, `cve-...txt` into the bundle as `snapshot.txt`, `cve.txt`
- (reports/ is gitignored — this task is not committed; it is the working proof.)

**Interfaces:**
- Consumes: `scripts/report/validate_findings.sh` from Task 1.

- [ ] **Step 1: Create the bundle dir and move the raw dumps**

```bash
mkdir -p reports/2026-07-10-158.160.2.43-full
# reports/ is gitignored, so plain mv (not git mv)
mv reports/snapshot-158.160.2.43-2026-07-10.txt reports/2026-07-10-158.160.2.43-full/snapshot.txt
mv reports/cve-158.160.2.43-2026-07-10.txt       reports/2026-07-10-158.160.2.43-full/cve.txt
```

- [ ] **Step 2: Move the reports and apply the three cosmetic fixes**

Move `reports/full-158.160.2.43-2026-07-10.md` → `reports/2026-07-10-158.160.2.43-full/report.md` and `...ru.md` → `.../report.ru.md`. In BOTH, apply:
  1. **Reorder:** move the `[INFO] howdie` finding block to the end of `## Findings`, after the `[LOW]` sysctl finding.
  2. **Header:** `cve ✅ (degraded — see below)` → `cve ✅`.
  3. **Coverage wording:** in the "Collector bug found" bullet, drop the "A backdoor account's `authorized_keys`…" framing and the "exactly how `howdie`'s keys were missed" clause; state it neutrally: "a home whose `.ssh` is `0700` and owned by another user is unreadable to a non-root audit; the collector now emits `UNREADABLE` and a blind-spot caveat instead of skipping silently."

- [ ] **Step 3: Author `findings.json` for the 11 findings**

Write `reports/2026-07-10-158.160.2.43-full/findings.json`:

```json
{
  "target": "158.160.2.43",
  "host": "intensa-site-server",
  "collected": "2026-07-10",
  "os": "Ubuntu 18.04.6 LTS",
  "posture": { "read_only": true, "hook_enforced": false },
  "surfaces": { "server": "ok", "ssh_logs": "not_collected", "web_logs": "not_collected", "cve": "ok" },
  "summary": { "critical": 3, "high": 3, "medium": 2, "low": 1, "info": 1 },
  "findings": [
    { "id": "patching-eol-no-esm", "severity": "critical", "area": "patching",
      "title": "Host receives no security updates (EOL release, no ESM)",
      "evidence": ["PRETTY_NAME=\"Ubuntu 18.04.6 LTS\"", "This machine is not attached to an Ubuntu Pro subscription."],
      "why": "18.04 standard support ended 2023-05-31; without ESM no fixes are published, so apt showing 0 updates means none exist.",
      "fix": "Rebuild on 22.04/24.04, or interim `sudo pro attach <token>` then apt upgrade.", "mitre": null, "status": "new" },
    { "id": "patching-kernel-unpatched", "severity": "critical", "area": "patching",
      "title": "Kernel 4.15.0-213 running 241 days, ~3 years without patches",
      "evidence": ["kernel: Linux 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:12 UTC 2023", "up 241 days"],
      "why": "Running kernel is the newest installed; LPE bugs fixed upstream since 2023 apply directly.",
      "fix": "Resolved by the ESM/rebuild decision; reboot afterwards.", "mitre": null, "status": "new" },
    { "id": "cve-scan-blind-on-eol", "severity": "critical", "area": "cve",
      "title": "CVE scan cannot see internet-facing daemons — its silence is an artifact",
      "evidence": ["219 unique CVEs across 451 source packages", "0 in CISA KEV", "nginx/openssh/openssl/mysql/php7.2: zero matches"],
      "why": "OSV records a Ubuntu package vuln only when a fix is published; EOL-no-ESM means no entries, so clean == unscanned.",
      "fix": "Get vuln data from ESM or the release upgrade; treat sshd 7.6p1 / nginx 1.14 as unpatched since 2023.", "mitre": null, "status": "new" },
    { "id": "access-offensive-tooling", "severity": "high", "area": "access",
      "title": "Offensive tooling (nikto, nmap) pre-installed on a production web server",
      "evidence": ["nikto 1:2.1.5-2", "nmap 7.60-1ubuntu5"],
      "why": "Ready-made recon/lateral-movement tools on the web host; no download needed post-compromise.",
      "fix": "sudo apt-get purge nikto nmap", "mitre": "T1046", "status": "new" },
    { "id": "access-intensa-shared-keys", "severity": "high", "area": "access",
      "title": "`intensa` is a shared team account holding 15 SSH keys, one anonymous",
      "evidence": ["authorized_keys: intensa keys=15 mtime=2026-07-03", "key: ssh-ed25519 (no comment)"],
      "why": "One uid for 15 people destroys the audit trail and makes offboarding unenforceable.",
      "fix": "Per-engineer accounts+keys; reduce intensa to one automation key; `ssh-keygen -lf` the anonymous key.", "mitre": "T1078", "status": "new" },
    { "id": "patching-web-eol-engines", "severity": "high", "area": "patching",
      "title": "Web tier runs three end-of-life engines behind a public port",
      "evidence": ["nginx 1.14.0 on 0.0.0.0:80,443", "php7.2 EOL 2020, php74 EOL 2022", "libssl1.0.0 OpenSSL 1.0.2 EOL 2019"],
      "why": "Public TLS and PHP stacks are years past upstream EOL; Apache installed but idle adds CVE surface.",
      "fix": "Release upgrade fixes nginx/PHP/OpenSSL; `sudo apt-get purge apache2*`; retire php7.2 if unused.", "mitre": null, "status": "new" },
    { "id": "ssh-root-login-by-key", "severity": "medium", "area": "ssh",
      "title": "Root login over SSH permitted by key",
      "evidence": ["permitrootlogin without-password"],
      "why": "A stolen root key bypasses the sudo audit trail; no AllowUsers/AllowGroups scoping.",
      "fix": "PermitRootLogin no + AllowGroups ssh-users; `sudo sshd -t && systemctl reload sshd`.", "mitre": null, "status": "new" },
    { "id": "patching-third-party-ppas", "severity": "medium", "area": "patching",
      "title": "Six third-party PPAs supply core system libraries",
      "evidence": ["ppa:sergey-dryabzhinsky/*", "ppa:ondrej/php", "19 packages incl. liblzma5, libpcre3, git"],
      "why": "Well-known PPAs (not compromise) but they feed core libs for an EOL suite and apt-daily pulls unattended.",
      "fix": "After upgrade, re-add only needed PPAs as signed-by-scoped .sources; drop duplicates.", "mitre": null, "status": "new" },
    { "id": "sysctl-hardening-toggles-off", "severity": "low", "area": "sysctl",
      "title": "Two kernel hardening toggles are off",
      "evidence": ["kernel.dmesg_restrict = 0", "net.ipv4.conf.all.accept_redirects = 1"],
      "why": "Unprivileged dmesg leaks addresses; host accepts ICMP redirects.",
      "fix": "sudo sysctl -w kernel.dmesg_restrict=1 net.ipv4.conf.all.accept_redirects=0; persist in /etc/sysctl.d/.", "mitre": null, "status": "new" },
    { "id": "access-howdie-owned-tooling", "severity": "info", "area": "access",
      "title": "Account `howdie` — attributed to the owner's own tooling (not a threat)",
      "evidence": ["howdie:x:999:999::/home/howdie:/bin/bash", "dead.letter: denied sudo nginx -t / php-fpm -t"],
      "why": "Operator-confirmed deploy/site-management tool; holds no privilege. Recorded so a future sweep does not re-flag it.",
      "fix": "No action. Optional hygiene: normal-range UID, drop systemd-journal if unused.", "mitre": null, "status": "new" }
  ]
}
```

- [ ] **Step 4: Validate the sidecar against the schema**

Run: `scripts/report/validate_findings.sh reports/2026-07-10-158.160.2.43-full/findings.json`
Expected: `WR-VALIDATE: OK (10 findings)` — 3 critical + 3 high + 2 medium + 1 low + 1 info = 10, matching the `summary` block.

- [ ] **Step 5: Confirm the whole suite still passes**

Run: `bats tests/`
Expected: all PASS (validator suite green; pre-existing suites unaffected).

- [ ] **Step 6: No commit (reports are gitignored)**

The bundle is the working proof, not a tracked artifact. Note in the session summary that `reports/2026-07-10-158.160.2.43-full/` now demonstrates the v2 layout.

---

## Notes for the executor

- The earlier bug-fix changes to `scripts/analyze/cve_scan.sh` and `scripts/collect/server_snapshot.sh` are uncommitted in the working tree and are unrelated to this plan. Do not fold them into Phase 1 commits; leave them for a separate commit decision.
- Phases 2 (HTML `render_html.sh`) and 3 (`diff_findings.sh` + `/wr retry`) are separate plans, written after Phase 1 lands.
