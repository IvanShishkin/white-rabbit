# Service version currency / end-of-life

Deterministic companion to the CVE scan. Where `cve_scan.sh` matches packages against OSV (and
goes blind on an EOL host with no ESM, because no fixes are published), `service_eol.sh` checks
the **installed version of each network-facing service against endoflife.date** — so an outdated
or unsupported nginx/php/mysql/openssl/node is caught by data, not by the model remembering
release dates.

Input: the `service_eol` section of `scripts/analyze/service_eol.sh <snapshot>`, one line per
tracked service:

```
WR-EOL: <product> <installed-upstream> cycle=<x.y> eol=<date|true|false> latest=<ver> status=<eol|outdated|current>
```

## Triage

### End-of-life service (status=eol)
- **id:** eol-service
- **area:** patching
- **severity:** the eol'd release no longer gets upstream security fixes. **High** by default;
  **critical** when the service terminates TLS or is directly internet-reachable (cross-check the
  `listening` section: bound to `0.0.0.0`/`[::]` on 80/443/the service port) — an unsupported
  public-facing daemon is a standing, unpatchable exposure.
- **why:** every vulnerability disclosed after the `eol=` date stays open forever on this host.
  This is exactly the gap the CVE scan cannot see on an EOL OS.
- **fix:** upgrade the service to a supported cycle (usually via the OS release upgrade for
  distro-packaged services, or the vendor repo). Name the specific supported target
  (e.g. "nginx 1.14 → a maintained 1.2x/1.3x", "php 7.2 → 8.2+", "MySQL 5.7 → 8.0/8.4").

### Behind-latest but supported (status=outdated)
- **id:** outdated-service
- **area:** patching
- **severity:** **low–medium** — the cycle is still maintained, but the installed patch level is
  behind `latest=`, so it is missing already-published fixes. Raise to medium if internet-facing.
- **fix:** apply the pending package updates for that service (`apt-get install --only-upgrade <pkg>`
  or the distro's security update path).

### Current (status=current)
- Not a finding. Report in "what's fine" only if useful; otherwise omit.

## Cross-checks (raise confidence / severity)
- **EOL service on a public port** → cross-reference `listening`: an eol service on `0.0.0.0:443`
  is critical, not high. This is the single most important escalation this catalog drives.
- **EOL service the CVE scan reported "zero matches" for** → the two together are the proof that
  "clean CVE scan" means *unscanned*, not *safe*. Cite both.
- Merge same-product multi-cycle rows sensibly (e.g. `openssl 1.0.2` *and* `1.1.1` both eol →
  one finding "OpenSSL 1.0.2 and 1.1.1 present, both EOL").

## Degradation
- `WR-NOTE: … not version-checked` — endoflife.date had no data for that product (unknown slug or
  source down). Report "not checked", never "current". Never invent a status.
