# White Rabbit — Guardrails (policy: source of truth)

White Rabbit performs **white-box, authenticated, strictly read-only** audits. It never
modifies any host. Fixes are emitted only as suggested commands the user runs themselves.

## Posture
- **Read-only by construction.** No command that mutates a host may run.
- **Fail closed.** If intent is ambiguous or the guard cannot parse its input, the command is denied.
- **No active exploitation.** No brute force, no exploit execution, no intrusive scanning.
- **No secrets in output.** `.env`, keys, and credentials never enter reports or logs.

## Enforcement (defense in depth)
1. **`hooks/guard.sh` (`PreToolUse`) — hard enforcement.** Intercepts every `Bash` tool
   call and denies it unless it passes all three checks below. Enforced by the Claude Code
   harness, not by model goodwill.
2. **`policy/denied-patterns.txt`** — extended-regex signatures of mutation. Any match → deny.
3. **`policy/allowed-commands.txt`** — read-only allowlist. The first token of every pipeline
   segment must be listed, or the command is denied.
4. **Output-redirection block** — any redirect to a file (not `/dev/null`, not an fd dup) → deny.

## The three checks (in order)
1. **Denylist:** the full command matches no pattern in `denied-patterns.txt`.
2. **Redirection:** after removing `>/dev/null`, `2>/dev/null`, and `N>&M` fd dups, no `>` remains.
3. **Allowlist:** splitting on `| || && ; &`, every segment's first token (after stripping leading
   `VAR=val` assignments and any directory path) is present in `allowed-commands.txt`.

A command is allowed only if it passes all three. Missing policy files, missing `jq`, or
unparseable input all result in **deny**.

## Known limitations (hardened in later plans)
- The server-side collector script (`scripts/collect/server_snapshot.sh`) may use `sudo -n` for a
  FIXED set of privileged READS (effective `sshd -T`, firewall status, socket owners) when passwordless
  sudo exists; it never uses sudo for mutation. This is server-side only — the local `PreToolUse`
  guard still denies `sudo` for ad-hoc local commands.
- Programmable engines (`awk`, `sed`) and command-runners (`env`, `xargs`) are deliberately NOT
  on the read-only allowlist in this foundation; audit playbooks needing them must opt in with
  tool-specific constraints.
- Quote-aware tokenization is not implemented: an operator character (`| && ; &`) appearing INSIDE
  quotes (e.g. `grep 'a|b' file`) is split and may be falsely DENIED (fail-closed, safe but can
  block legitimate reads such as `grep -E 'sshd|sudo'`). The log-hunt plan must address this.
- SSH remote: the outer `ssh` is allowlisted; an inner non-mutating-but-unknown binary is not
  allowlist-checked (the denylist still scans the whole command string for mutations, including
  full-path forms).
- Command-string analysis is best-effort; a novel mutator not in the denylist, invoked in a
  context the parser can't tokenize, could slip through. Vetted read-only collector scripts are
  the real mitigation.
- Rare false-positive: reading a file whose final path component is literally a denied command
  name (e.g. `cat /etc/rm`) is denied.
- Write-capable allowlisted tools (`openssl`, `sort`, `dpkg`, `rpm`, `sysctl`, `iptables`, `nft`,
  `crontab`, `journalctl`, `hostname`, `sshd`, `date`) are kept on the allowlist for their read
  subcommands/flags but constrained to read-only use by the denylist on a **best-effort** basis:
  the denylist enumerates their known write flags and mutating subcommands (e.g. `sort -o`,
  `dpkg -i`, `sysctl key=value`, `nft -f`, `crontab -`, `journalctl --rotate`, `hostname NAME`,
  bare/`-D` `sshd`). An **unenumerated** write flag on one of these tools, or a mutator invoked in
  a context the line-oriented parser cannot tokenize, could still slip through. Vetted read-only
  collector scripts remain the real mitigation. Programmable in-place writers (`sed`, `awk`, `yq`)
  are kept off the allowlist entirely for the same reason.
- `ssh -F <custom-config>` can indirectly carry `ProxyCommand`/`LocalCommand` directives from a
  config file the parser cannot inspect, which would execute a command on the auditor host. Direct
  `-o ProxyCommand`/`-o LocalCommand`/`-o PermitLocalCommand` forms **are** denied; the indirect
  config-file path is a residual best-effort gap.
- `openssl ca` and similar subcommands can mutate a CA database (e.g. `index.txt`) without a
  `-out` flag, so they are not caught by the `-out`/`-keyout`/`-writerand` write-flag denial and
  are covered only by the best-effort read-only posture.
