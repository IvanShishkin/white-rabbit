# Checks — OS-package CVEs (`cve` section)

Read the `cve` section produced by `scripts/analyze/cve_scan.sh`:
`WR-CVE: <pkg> <installed> <cve-id> sev=<crit|high|medium|low> epss=<0..1|-> kev=<yes|no|-> fixed=<ver>`
lines, `WR-CVE-SUPPRESSED:` lines (VEX-accepted), and `WR-NOTE:` caveats.

Only **actionable** findings appear (a fixed version exists in the distro). Matches without
a fix are counted in a note — mention them, do not turn them into findings. The scan is keyed
by **source package** (that is how Ubuntu/Debian advisories work), so one WR-CVE line may
cover several installed binary packages.

**Degradation rules (trust the dashes):** `epss=-` / `kev=-` means that source was
unreachable — say prioritization is degraded, never guess the missing value. A
`cve source (OSV.dev) unreachable` note means the scan did not run: report "no CVE data",
not "no CVEs".

### Known-exploited vulnerability present (CISA KEV)
- **id:** cve-kev-known-exploited
- **severity:** critical
- **look for:** `kev=yes` on any WR-CVE line (the scanner already sets `sev=crit`).
- **why:** KEV means exploitation observed in the wild — this is no longer a probability,
  it is an active attacker capability against your exact package. Patch-today material,
  regardless of CVSS aesthetics.
- **fix:** `# patch just this package now: sudo apt-get update && sudo apt-get install --only-upgrade <pkg>  (rpm: sudo dnf update <pkg>)`
- **mitre:** T1190 (Exploit Public-Facing Application) / T1068 (Privilege Escalation) for kernel/local packages

### High exploitation probability (EPSS) or critical advisory
- **id:** cve-high-epss
- **severity:** high
- **look for:** `sev=high` — EPSS above 0.5 (more likely than not to be exploited within
  30 days) or the distro advisory rates it critical.
- **why:** EPSS ranks real-world exploitation likelihood; a 0.5+ score puts the CVE in the
  top fraction of a percent of all CVEs. Prioritize network-facing packages (openssl,
  openssh, nginx, kernel) first.
- **fix:** `# upgrade the affected package to the fixed version from the WR-CVE line: sudo apt-get install --only-upgrade <pkg>`
- **mitre:** T1190 (Exploit Public-Facing Application)

### Moderate-priority fixable CVE
- **id:** cve-medium-fixable
- **severity:** medium
- **look for:** `sev=medium` — EPSS in the 0.1–0.5 band, or a high-rated advisory without
  EPSS signal.
- **why:** Real but not urgent-today; batch these into the next patch window rather than
  firefighting one by one.
- **fix:** `# include in the next maintenance window: sudo apt-get upgrade  (review the list first: apt list --upgradable)`

### Low-priority backlog CVE
- **id:** cve-low-backlog
- **severity:** low
- **look for:** `sev=low` lines.
- **why:** Fixable but with negligible exploitation signal. Report the count, list the top
  few; unattended-upgrades will usually absorb these.
- **fix:** `# keep automatic security updates on: sudo dpkg-reconfigure -plow unattended-upgrades`

### VEX-suppressed findings (accepted risk)
- **id:** cve-vex-suppressed
- **severity:** info
- **look for:** `WR-CVE-SUPPRESSED: <pkg> <cve> reason=<justification>` lines (rules live in
  `targets/vex.txt`: `<CVE-id> <pkg|*> <justification>`).
- **why:** A documented accept/not-applicable decision. Show them in a separate "suppressed"
  block so the acceptance stays visible and reviewable — an outdated justification is itself
  a finding.
- **fix:** `# re-review the justification; drop the line from targets/vex.txt to re-surface the CVE`

## Posture note (report it once, verbatim-ish)
The scan runs on the **auditor machine**: the audited host only ever executes the read-only
`packages` inventory (dpkg-query/rpm). Live matching sends **package names/versions and CVE
ids** (public, low-sensitivity) over HTTPS to OSV.dev, FIRST.org (EPSS) and CISA (KEV) —
no hostnames, IPs or secrets leave the auditor.
