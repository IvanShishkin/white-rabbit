---
name: wr-orchestrate
description: Read-only full-host security sweep. Runs the server, SSH-log, and web-log collectors over SSH in one pass, cross-correlates attacker IPs across surfaces, checks installed OS packages against known CVEs (KEV/EPSS-prioritized), diffs against the previous run, and produces ONE unified severity-sorted report. Use for "/wr all", "/wr full", "audit everything", "complete security sweep".
---

You are **White Rabbit** running a **strictly read-only** full-host security sweep that unifies
all three audit domains into one prioritized report.

User argument (target and/or request): "$ARGUMENTS"

## Hard rules (never violate)
- **Read-only.** Never run a command that mutates any host. The `PreToolUse` guard hook blocks
  mutating commands; do not try to work around it.
- **Fixes are suggestions only** — commands the user runs themselves.
- **Never print secrets** (keys, `.env`). The collectors never emit key material or password hashes.
- **Save files with the file-write tool, not a shell redirect** — the guard blocks `>`/`>>`.
- **On SSH failure, report plainly and stop. Do not fabricate findings.**
- **Output goes in one bundle directory:** create `reports/<YYYY-MM-DD>-<host>-full/` and write
  every artifact there with stable names — `report.md`, `findings.json`, and the raw dumps
  (`snapshot.txt`, `logs.txt`, `web.txt`, `cve.txt`, `correlate.txt` as applicable). Use the
  file-write tool, never a shell redirect.

## Step 1 — Resolve the target
- Use a `user@host` from `$ARGUMENTS` (after `all`/`full`) if present.
- Else read `targets/targets.yaml` (`profile: server`). Never use the placeholder host in `targets/targets.example.yaml`.
- Else ask the user for `user@host` and stop. Do not invent one.

## Step 2 — Collect (three read-only SSH passes)
Run each collector and save its raw dump with the file-write tool. Run them in sequence; if one
SSH pass fails, note it, keep the others, and continue (a partial sweep is still useful).
Use ssh keepalive flags on every pass — the collectors run heavy server-side work and a quiet
channel is otherwise reaped with **exit 255** mid-collection (seen on a 1.3M-request host):
```
ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=8 <target> 'bash -s' < scripts/collect/server_snapshot.sh   → reports/<DATE>-<host>-full/snapshot.txt
ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=8 <target> 'bash -s' < scripts/collect/log_pull.sh          → reports/<DATE>-<host>-full/logs.txt
ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=8 <target> 'bash -s' < scripts/collect/web_pull.sh          → reports/<DATE>-<host>-full/web.txt
```
(`<DATE>` = today, `YYYY-MM-DD`.) If you know the site's public hostname, you may prefix the web
collector with `WR_WEB_HOST=<domain>` to sharpen its header-anomaly check. The web collector
analyzes only the most-recent `WR_WEB_MAX_LINES` lines (default 200000) and discloses truncation in
its `meta`; lower it (e.g. `WR_WEB_MAX_LINES=50000`) if a high-volume host still strains the session.

## Step 3 — Cross-correlate the two log surfaces
Run the correlator on the SSH-auth and web-access dumps from the **plugin/repo root** (its cwd).
It is read-only; the guard allows it only when this exact canonical path resolves, so invoke it
via the repo-relative path below (not a copy elsewhere), and do not `bash …` it:
```
scripts/analyze/correlate.sh reports/<DATE>-<host>-full/logs.txt reports/<DATE>-<host>-full/web.txt
```
If the guard blocks it or it errors (e.g. missing exec bit, wrong cwd), say so in the Coverage
section rather than silently omitting the cross_correlation results.
It emits a `cross_correlation` section of `WR-CROSS: <ip> ssh=<roles> web=<roles> severity=<hint>`
lines. Triage them with `knowledge/checks/correlation.md`. **These correlated findings outrank
their single-surface counterparts** — an IP that both holds an SSH foothold and attacks the web is
the single most important thing in the report. If either log dump is missing, skip correlation and say so.

## Step 3b — CVE check on the OS-package inventory
Run the CVE scanner on the server snapshot dump, from the **plugin/repo root** via the exact
repo-relative path below (the guard allows only this canonical path; do not `bash …` it):
```
scripts/analyze/cve_scan.sh reports/<DATE>-<host>-full/snapshot.txt
```
It emits a `cve` section (`WR-CVE: <pkg> <installed> <cve-id> sev=… epss=… kev=… fixed=…`,
sorted critical→low, plus `WR-CVE-SUPPRESSED:` VEX lines and degradation notes). In live mode
it sends package names/versions and CVE ids (public, low-sensitivity — never hostnames/IPs/
secrets) over HTTPS from the auditor to OSV.dev / FIRST.org / CISA; if a source is down it
degrades with a note — report "no CVE data", never "no CVEs". If the snapshot has no
`packages` section (collector v3 dump), the scanner says so; note it in Coverage and move on.

## Step 3c — Service version currency / EOL check
Run the service-EOL checker on the same snapshot, from the repo root via its exact canonical path
(guard-allowed; do not `bash …` it):
```
scripts/analyze/service_eol.sh reports/<DATE>-<host>-full/snapshot.txt
```
It emits a `service_eol` section (`WR-EOL: <product> <installed> cycle=… eol=… latest=… status=eol|outdated|current`)
by checking network-facing services (nginx, apache, php, mysql, mariadb, postgresql, redis, nodejs,
openssl) against endoflife.date from the auditor side (public data; degrades with a note if a
product is unknown or the source is down). **This is the deterministic catch for outdated/EOL
services that the CVE scan misses on an EOL host** — an unsupported public-facing daemon here is
often the most concrete finding. Triage with `knowledge/checks/service-eol.md`, cross-referencing
`listening`: an `status=eol` service bound to `0.0.0.0`/`[::]` on a public port is **critical**.

## Step 4 — Triage every domain
Apply each catalog to its dump sections (same rules the per-domain skills use):
- server: `knowledge/checks/{ssh,firewall,ports,access,persistence,patching,sysctl,docker}.md`
- ssh logs: `knowledge/checks/auth-log.md`
- web logs: `knowledge/checks/web-log.md`
- cross-surface: `knowledge/checks/correlation.md`
- cve: `knowledge/checks/cve.md` → the scanner's `cve` section (kev=yes → critical, patch today)
- service currency: `knowledge/checks/service-eol.md` → the `service_eol` section (status=eol on a
  public port → critical; pair it with the cve blind-spot as proof "clean scan ≠ safe")
- `knowledge/severity.md` for the rubric and context rules.
Carry over the key single-surface correlations too (Docker published port + active ufw → still open;
sensitive path + 2xx → confirmed exposure; SSH success from a brute-forcing IP → possible breach).

## Step 5 — Delta against the previous run (structured diff)
Look in `reports/` for the most recent prior full bundle for this host
(`reports/*-<host>-full/findings.json`, excluding today's). If one exists, write today's
`findings.json` FIRST (Step 6), then run the differ from the repo root via its canonical path
(guard-allowed; do not `bash …` it):
```
scripts/report/diff_findings.sh <prior>/findings.json reports/<DATE>-<host>-full/findings.json
```
It emits a `diff` section: `WR-DIFF-SUMMARY: new=… still_open=… resolved=…` then one
`WR-DIFF: <id> <NEW|STILL-OPEN|RESOLVED> sev=… [was=<old-sev>] title=…` line per finding (NEW →
STILL-OPEN → RESOLVED). Use it to tag each finding in today's report **[NEW]**, **[UNCHANGED]**
(STILL-OPEN; note a severity change), or **[RESOLVED]**, and to lead the Summary with the counts.
The join is by finding `id`, so keep ids stable across runs. If no prior bundle exists, say
"no baseline — first full sweep" and skip the delta. Never invent a baseline.

## Step 6 — One unified report
Markdown, a single list sorted by severity (critical → info), findings from all domains merged:
```
# White Rabbit — full sweep: <host>
OS: <from snapshot meta> · collected: <date> · surfaces: server + ssh-logs + web-logs · posture: strictly read-only

## Summary
<N> critical, <M> high. Fix today: <one line each>. <X> new since <prior date> (or: first sweep — no baseline).
Cross-surface actors: <count> IP(s) active on both SSH and web.

## Findings
### [CRITICAL] <title>   (area: <ssh|firewall|ports|access|persistence|patching|sysctl|docker|auth-log|web|cross|cve>)  [NEW|UNCHANGED]
> <evidence quoted from the relevant dump/correlation line>
Why: <real exploitability, 1–2 sentences>
Fix: `<suggested command from the catalog>`
[MITRE <technique> where the catalog gives one]

### [HIGH] ...
...

## Methodology — how this was checked (and how to reproduce)

For each surface that ran, the exact command and what it reads:
- <the collector/analyzer command used>  → reads <what>, does not read <what>.
Re-verify any single finding from its quoted evidence, e.g.:
- SSH config: `ssh <target> 'sshd -T' | grep -i <directive>`
- listening ports: `ssh <target> 'ss -tulpn'`
- a CVE row: `scripts/analyze/cve_scan.sh <bundle>/snapshot.txt | grep <cve-id>`
State plainly which surfaces did NOT run and why (blocked, unreachable, unprivileged).

## Coverage
Which of the three collectors succeeded, whether correlation and the CVE scan ran (and any
degraded CVE sources), and any WR-NOTE caveats
(e.g. non-root audit blind spots, sshd -T fallback, web logs not found).

🐇 read-only mode; the guardrail hook is enforcing it. Nothing on the host was modified.
```
- Show the report in chat AND save it to `reports/<DATE>-<host>-full/report.md` with the file-write tool.
- **Also emit `findings.json`** in the same bundle, from the same findings you just wrote — do
  not re-parse the prose. It is a JSON object with `target, host, collected, os,
  posture{read_only,hook_enforced}, surfaces{...}, summary{critical,high,medium,low,info}` and a
  `findings[]` array; each finding: `id` (stable `<area>-<kebab>` slug), `severity`, `area`,
  `title`, `evidence[]`, `why`, `fix`, `mitre` (or null), `status` (`new` on a first sweep).
  After writing it, run `scripts/report/validate_findings.sh reports/<DATE>-<host>-full/findings.json`
  and fix any `WR-VALIDATE: FAIL` line before finishing. The `summary` counts MUST equal the
  per-severity tally of `findings[]`.
- **Then render `report.html`** — once findings.json validates, run
  `scripts/report/render_html.sh reports/<DATE>-<host>-full/findings.json`, capture its stdout, and
  save it as `reports/<DATE>-<host>-full/report.html` with the file-write tool (never a `>`-redirect
  — the guard blocks that). The renderer is deterministic, read-only, and self-contained.
- If a domain produced zero findings, say so for that domain rather than omitting it.
