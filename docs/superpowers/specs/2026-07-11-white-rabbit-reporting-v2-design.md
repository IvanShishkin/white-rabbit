# White Rabbit — Reporting v2 (design spec)

Date: 2026-07-11 · Status: approved for planning · Author: Ivan Shishkin + White Rabbit

## Problem

The current audit report is a single hand-written markdown file per run, dropped flat into
`reports/`. Three needs are unmet:

1. **Reproducibility.** A reader cannot see *how* a finding was obtained or re-verify it
   without reverse-engineering the session. There is no "methodology / how to reproduce" block.
2. **Executive delivery.** There is no clean, professional, emoji-free HTML rendering suitable
   for management.
3. **Re-checking.** There is no deterministic way to take a prior report and ask "what did we
   fix, what is still open, what is new" — the existing delta step is model-prose only.

All three are hard to build on top of prose. The report is written as free text, so HTML
rendering and diffing would each have to re-parse that prose — fragile.

## Goals

- Keep **`report.md` as the human-facing default**, authored by the model as it is today
  (rich prose, judgement, context — that quality must not regress).
- Emit a **structured `findings.json` sidecar** alongside it, so HTML and diff consume data,
  never prose.
- Add a **Methodology / How to reproduce** section to every report.
- Generate a **strict, self-contained, emoji-free `report.html`** for executives.
- Provide a **deterministic `/wr retry`** that diffs a new run against a prior report's
  `findings.json` and produces a focused re-check report.
- Store each run as a **self-contained directory bundle**.

## Non-goals

- Not replacing model-authored prose with templated prose. The model still writes `report.md`.
- Not a web server / live dashboard. HTML is a static, self-contained file.
- Not changing the collectors or analyzers' read-only posture. Analyzers still print to stdout.
- Not auto-committing or auto-sending reports anywhere.

## Architecture

### 1. Storage — per-run directory bundle

Replace flat `reports/<kind>-<host>-<date>.<ext>` with one directory per run:

```
reports/<YYYY-MM-DD>-<host>/
  report.md          # human default — model-authored, unchanged in spirit
  report.html        # generated (Phase 2); strict, emoji-free
  findings.json      # structured sidecar — model emits alongside report.md
  snapshot.txt       # raw server snapshot dump
  logs.txt           # raw ssh-auth dump      (when collected)
  web.txt            # raw web-access dump     (when collected)
  cve.txt            # cve_scan.sh output
  correlate.txt      # correlate.sh output     (when both log dumps exist)
```

- Directory name: **date first** (`2026-07-11-158.160.2.43`) so `ls` sorts chronologically.
- Host component is the target host/IP as given (same value used in report titles today).
- Raw dumps lose the `<host>-<date>` suffix in their filename — the directory carries that
  context now. Filenames become stable (`snapshot.txt`, not `snapshot-<host>-<date>.txt`).
- `reports/.gitkeep` stays; bundles remain gitignored as today.

### 2. `findings.json` — structured sidecar

The model writes this **in the same step** it writes `report.md`, from the same analysis — no
second pass, no parsing of the prose. Contract: a JSON object.

```json
{
  "target": "158.160.2.43",
  "host": "intensa-site-server",
  "collected": "2026-07-11",
  "os": "Ubuntu 18.04.6 LTS",
  "posture": { "read_only": true, "hook_enforced": false },
  "surfaces": { "server": "ok", "ssh_logs": "not_collected",
                "web_logs": "not_collected", "cve": "ok" },
  "summary": { "critical": 3, "high": 3, "medium": 2, "low": 1, "info": 1 },
  "findings": [
    {
      "id": "patching-eol-no-esm",
      "severity": "critical",              // critical|high|medium|low|info
      "area": "patching",                  // ssh|firewall|ports|access|persistence|patching|sysctl|docker|auth-log|web|cross|cve
      "title": "Host receives no security updates (EOL release, no ESM)",
      "evidence": ["PRETTY_NAME=\"Ubuntu 18.04.6 LTS\"", "not attached to an Ubuntu Pro subscription"],
      "why": "Every CVE disclosed in ~3 years is unpatched; apt shows 0 updates because none exist.",
      "fix": "Rebuild on 22.04/24.04, or interim `sudo pro attach <token>` then apt upgrade.",
      "mitre": null,                       // e.g. "T1078" or null
      "status": "new"                      // new|unchanged|resolved (set by retry; "new" on a first sweep)
    }
  ]
}
```

- **`id`** is a stable slug (`<area>-<short-kebab>`), used as the diff key (see Retry). The
  model assigns it; it must be stable for the same underlying issue across runs.
- Severity/area enums mirror the existing catalogs and `knowledge/severity.md`.
- `report.md` and `findings.json` must agree on counts and severities — enforced by a
  consistency check in Phase 1 tests (parse both, compare the summary line to the array).

### 3. Methodology / How to reproduce (report content)

New required section near the end of `report.md` (before Coverage), and mirrored as a
`methodology` array is **not** needed in JSON — it is prose-only. It states, per surface that
ran:

- the exact command used (the collector SSH invocation, `correlate.sh`, `cve_scan.sh`),
- what that command reads and what it deliberately does not,
- how to re-derive a specific finding from its quoted evidence (e.g. "re-run
  `ssh <t> 'sshd -T' | grep -i permitrootlogin` to confirm the SSH finding").

This formalizes the manual verification done ad hoc today. It is authored by the model from a
checklist the skill provides, so it stays honest about what actually ran vs. was blocked.

### 4. HTML executive rendering (Phase 2)

`scripts/report/render_html.sh <bundle-dir> > <bundle-dir>/report.html`

- Reads `findings.json` (via `jq`, already a hard dependency) for the structured summary and
  the findings table; reads `report.md` for the prose bodies.
- Output is a **single self-contained HTML file**: inline CSS, no external fonts/scripts/images,
  no network. Strict professional style — no emoji, no rabbit, muted palette, a severity summary
  band at the top (counts), then findings sorted critical→info, then Coverage/Methodology.
- Deterministic: same input → same output. Templated in the script, not model-authored.
- Read-only posture: the script prints HTML to stdout; the model saves it with the file-write
  tool, exactly like `report.md`/`cve.txt` today. No in-script file writes → still passes the
  "read-only by construction" test pattern used for the analyzers.
- Tested with a fixture bundle (`tests/fixtures/report/findings.json` + `report.md`) asserting:
  emoji absent, all findings present, counts match, no external URLs, valid single-root HTML.

### 5. Retry — deterministic re-check (Phase 3)

`scripts/report/diff_findings.sh <old/findings.json> <new/findings.json>`

- Joins by `id`. Emits, to stdout, machine lines:
  `WR-DIFF: <id> <RESOLVED|STILL-OPEN|NEW> sev=<severity> title=<title>`
  - in old, not in new  → `RESOLVED`
  - in both             → `STILL-OPEN` (report severity change if it moved)
  - in new, not in old  → `NEW`
- Read-only, stdout-only, `jq`-based; same posture and test pattern as the other analyzers.

Command surface: **`/wr retry [report-dir]`** (routed in `commands/wr.md`).
- With no arg: pick the most recent prior bundle for the resolved target.
- Re-runs the same collection the prior bundle used (server/logs/web as available), writes a new
  bundle, runs `diff_findings.sh` old→new, and the model writes a **re-check report** whose
  Summary leads with "Resolved N, still open M, new K since <prior date>", each finding tagged
  from the diff. `status` in the new `findings.json` is set from the diff
  (`resolved`/`unchanged`/`new`).
- This supersedes wr-orchestrate Step 5's prose-only delta with the structured diff; the skill
  text is updated to call the script rather than eyeball prior prose.

## Phasing

- **Phase 1 — bundle + sidecar + methodology.** Change output paths to the directory bundle in
  `commands/wr.md`, `skills/wr-orchestrate/SKILL.md`, and the four domain skills
  (`wr-server-audit`, `wr-log-hunt`, `wr-web-hunt`, `wr-cve`). Add the `findings.json` contract
  and the Methodology section to the report template in each skill. Add a bats test that
  validates a sample `findings.json` against the schema and checks md/json summary agreement.
- **Phase 2 — HTML.** `scripts/report/render_html.sh` + fixture + bats tests. Add `/wr` routing
  so status/`html` can (re)generate it for an existing bundle.
- **Phase 3 — retry.** `scripts/report/diff_findings.sh` + `/wr retry` routing in `commands/wr.md`
  + wr-orchestrate Step 5 rewrite + bats tests for the diff (RESOLVED/STILL-OPEN/NEW, severity
  moves, empty/missing inputs degrade cleanly).

Each phase ships independently and leaves the tool working.

## Testing

- bats, matching the existing suites. New analyzer scripts follow the "read-only by
  construction" grep test (no `>` to files, no mutating verbs) already used for
  `cve_scan.sh`/`correlate.sh`.
- Guard: `render_html.sh` and `diff_findings.sh` are added to the canonical-path allowlist in
  `hooks/guard.sh` (like `correlate.sh`/`cve_scan.sh`) so they run locally but only from their
  vetted repo paths.
- No network in tests (HTML/diff are offline by nature; no new fetchers).

## Open sub-decisions (defaulted; flag to change)

- Sidecar format: **JSON** (reuses `jq`; `yq` not a dependency). Defaulted over YAML.
- HTML: **generator script**, not model-authored, for repeatable strict styling.
- `report.md` stays emoji-branded (the 🐇 posture line); only `report.html` is strictly
  emoji-free.

## Consistency fixes to the existing 2026-07-10 report (independent, do alongside Phase 1)

Carried over from review; not part of the feature but should land: reorder `howdie` [INFO] to
the end, drop the stale "cve degraded" header label, and remove the "backdoor account" framing
from the collector-bug Coverage bullet now that `howdie` is attributed.
