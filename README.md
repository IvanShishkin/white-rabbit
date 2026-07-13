![White Rabbit](assets/banner.png)

# White Rabbit 🐇

**A read-only, white-box security audit copilot that runs inside [Claude Code](https://claude.com/claude-code).**

White Rabbit is not a scanner. It is an *orchestrator*: it collects data from your own
infrastructure using native, read-only commands, then leans on Claude to triage the findings by
**real-world exploitability** and cut the noise.

> A raw scanner hands you 500 "vulnerabilities."
> White Rabbit tells you: **"Fix these three today. The rest is noise — and here's why."**

The name is a double meaning: **white**-box (authenticated) auditing, and *"follow the white
rabbit"* — tracing what's hidden in your logs and code down to the root cause.

---

## Principles

- **Strictly read-only, by construction.** The tool never changes a host. Fixes are emitted as
  ready-to-run commands you execute yourself. A `PreToolUse` guard hook enforces this — any
  mutating command is blocked before it runs, not merely discouraged.
- **Zero-install collection.** Claude reaches your host over SSH and gathers evidence with tools
  that are already there (`ss`, `journalctl`, `dpkg`, `ufw status`, config reads). Nothing is
  installed on the audited server.
- **The brain is markdown, not code.** New audit capabilities are added declaratively — a new
  playbook in `skills/` and a reference sheet in `knowledge/` — rather than a new scanner binary.
- **Prioritization over enumeration.** Findings are scored by exploitability (e.g. a sensitive
  path served with a `200` is *critical*; the same path returning `403` is reconnaissance), and
  cross-correlated across surfaces (an attacker IP seen both brute-forcing SSH and probing the web
  app is escalated).
- **Active exploitation is out of scope.** No brute-forcing, no exploit execution, no intrusive
  pentesting — a deliberate boundary for safety and legality.

## Requirements

- [Claude Code](https://claude.com/claude-code)
- SSH access to the host(s) you want to audit
- `jq` on the machine running Claude Code (the guard fails closed without it)
- [`bats`](https://github.com/bats-core/bats-core) to run the test suite (development only)

## Install

White Rabbit is a Claude Code plugin. Clone it and point Claude Code at the directory as a
plugin, then run `/wr` from any session:

```bash
git clone https://github.com/IvanShishkin/white-rabbit.git
```

Configure the target host in `targets/targets.yaml` (copy `targets/targets.example.yaml`), or pass
`user@host` inline on any command.

## Usage

Run `/wr` with no argument for status, or route to an audit domain:

| Command | What it does |
|---------|--------------|
| `/wr` | Status: active guardrails, available domains, linked extensions |
| `/wr server [user@host]` | Host hardening: SSH config, firewall, listening ports, **persistence pack** (accounts, sudo/docker-group, `authorized_keys`, cron/timers, rootkit signals, patch level, sysctl, Docker exposure) |
| `/wr logs [user@host]` | SSH/auth intrusion hunt: brute force, user enumeration, successful logins from attacker IPs |
| `/wr web [user@host]` | HTTP access-log hunt (nginx / Caddy): sensitive-file exposure, scanners, login brute-force, path payloads, header anomalies |
| `/wr cve [user@host]` | OS-package CVE check against OSV.dev, prioritized by CISA **KEV** and **EPSS**, with fixed versions |
| `/wr all [user@host]` | Full sweep: every collector + cross-surface IP correlation + CVE check + delta vs. the previous run, in one severity-sorted report |
| `/wr <extension> …` | Route to a [linked extension](#extensions) |

Every run ends with a posture confirmation that the read-only guardrail was enforced and nothing
on the host was modified.

## What it checks

| Domain | Status | Highlights |
|--------|--------|-----------|
| Server hardening & persistence | **MVP** | UID-0 duplicates, empty passwords, passwordless sudo, docker-group members, `authorized_keys` inventory, cron/systemd persistence, `ld.so.preload` / deleted-binary processes / SUID, patch level & EOL, sysctl hardening, published Docker ports that bypass `ufw` |
| Log / intrusion detection | **MVP** | SSH auth brute force, successful logins correlated to attacker IPs, HTTP scanners, sensitive-file exposure (2xx correlation), payloads in request paths |
| Cross-surface correlation | **MVP** | Set-intersection of attacker IPs across SSH and web; accepted-SSH + web activity = critical foothold |
| OS-package CVEs | **MVP** | OSV.dev matching by source package, KEV/EPSS prioritization, VEX suppression, actionable (fix-available) findings only |
| Code audit (SAST, secrets) | Planned | — |
| App-dependency CVEs & reachability | Planned | — |

## Architecture

White Rabbit is layered so that extending the "brain" means writing markdown, not code:

- **Playbooks — `skills/`.** Each audit domain is a skill: what to check, which read-only commands
  collect the evidence, how to interpret it, and how to score severity.
  (`wr-server-audit`, `wr-log-hunt`, `wr-web-hunt`, `wr-cve`, `wr-orchestrate`.)
- **Reference catalogs — `knowledge/`.** Per-check reference sheets and the shared severity model
  that the playbooks reason against.
- **Collectors — `scripts/collect/`.** Small, strictly read-only shell scripts piped to the host
  over SSH (`ssh host 'bash -s' < collector.sh`). They normalize host output into a stable,
  labeled contract the playbooks parse. Designed for portability (BSD/GNU/mawk) and for high-volume
  hosts (bounded memory, streaming, SSH keepalive).
- **Analyzers — `scripts/analyze/`.** Auditor-side correlation and CVE matching that run against
  the collected dumps, never against the live host.

## Guardrails

Read-only posture is defined in two places:

- **Declaration:** [`policy/guardrails.md`](policy/guardrails.md), with the machine-readable
  `policy/allowed-commands.txt` (read-only binary allowlist) and `policy/denied-patterns.txt`
  (mutation signatures).
- **Enforcement:** [`hooks/guard.sh`](hooks/guard.sh), a `PreToolUse` hook that inspects every
  `Bash` invocation and **denies** it unless it passes three checks — no mutating pattern, no file
  redirection, and every pipeline segment's leading binary is on the allowlist. It **fails closed**
  (no `jq`, unparseable input, or missing policy files all deny). White Rabbit's own analysis
  scripts are trusted by *exact canonical path*, never by basename, so a same-named script planted
  elsewhere does not pass.

### Turning enforcement on

The guard **denies by default** — everything not on the read-only allowlist — so it belongs in a
session that does nothing but audit, not one where you also develop or run other tooling. Enable it
in one of two ways:

- **As the plugin.** Enabling White Rabbit as a Claude Code plugin wires the guard via
  `hooks/hooks.json` for every session the plugin is active in. Keep it enabled only in
  audit-dedicated setups.
- **As a marker-gated hook** *(recommended if you keep it installed all the time)*. Add a
  `PreToolUse` hook that stays dormant until you opt a session in with the `WR_ENFORCE` marker, so
  your normal sessions are untouched:

  ```json
  {
    "matcher": "Bash",
    "hooks": [
      {
        "type": "command",
        "command": "if [ \"${WR_ENFORCE:-}\" = \"1\" ]; then exec /abs/path/to/white-rabbit/hooks/guard.sh; fi"
      }
    ]
  }
  ```

  Then launch a read-only audit session with the marker set:

  ```bash
  WR_ENFORCE=1 claude
  ```

  In that session every mutating or non-allowlisted `Bash` command is blocked by `guard.sh`;
  sessions without the marker are completely unaffected. Hooks load at session start, so set the
  marker at launch — a session started without it is not guarded.

## Extensions

You can plug external agent projects into White Rabbit by symlinking them into `extensions/`
(contents are gitignored):

```bash
ln -s /path/to/your-scanner extensions/your-scanner
```

The symlink name becomes the route: `/wr your-scanner …`. Discovery is automatic — `/wr` status
lists everything linked. An extension may describe itself with a `wr-extension.md` manifest
(falling back to `CLAUDE.md`, then `README.md`). Extensions run under the **same read-only guard**:
their binaries are not auto-allowed — you opt each one in via `policy/allowed-commands.local.txt`
(gitignored, user-maintained). See [`extensions/README.md`](extensions/README.md) for details.

## Project layout

```
commands/          /wr slash-command router
skills/            audit-domain playbooks (the "brain")
knowledge/         per-check reference catalogs + severity model
scripts/collect/   read-only SSH collectors
scripts/analyze/   auditor-side correlation & CVE matching
scripts/extensions/ extension discovery
policy/            guardrail declaration, allow/deny lists
hooks/             PreToolUse read-only guard
targets/           host inventory (example provided)
tests/             bats behavioral tests
docs/              design spec & backlog
```

## Development

```bash
bats tests/     # run the full behavioral suite
```

Collectors and analyzers are covered by behavioral tests that exercise real logic against fixture
trees and stubbed tools — no live host required. Contributions keep the read-only invariant: new
collection commands must pass the guard, and mutation is never introduced.

## Roadmap

Threat-intel enrichment of top attacker IPs (AbuseIPDB), passive perimeter checks (TLS / cert
expiry / security headers), report delivery to Slack, and scheduled recurring runs. See
[`docs/backlog.md`](docs/backlog.md) for the working list and [`docs/design.md`](docs/design.md)
for the full design.

## License

MIT © Ivan Shishkin
