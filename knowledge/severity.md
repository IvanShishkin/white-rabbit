# White Rabbit — severity rubric (server-audit slice)

A simple, transparent scale for this slice. (The full risk-scoring engine —
CVSS × EPSS × KEV × asset-criticality — is a later cross-cutting layer.)

| level | meaning | examples |
|-------|---------|----------|
| **critical** | Immediate compromise risk; fix today. | empty SSH passwords; telnet open to the internet; no firewall AND a database port exposed to 0.0.0.0. |
| **high** | Serious weakness, likely exploitable. | `PermitRootLogin yes`; password auth enabled and exposed; no active firewall. |
| **medium** | Real weakness, needs context to exploit. | unexpected service listening on all interfaces; password auth enabled but port 22 firewalled. |
| **low** | Hardening gap, low impact. | `X11Forwarding yes`; permissive `MaxAuthTries`. |
| **info** | Informational; no action required. | observed OS/version; expected services. |

## Triage rules
- **Context lowers or raises severity.** Example: `PasswordAuthentication yes` is *high* if port 22 is reachable from anywhere, but *medium* if the firewall restricts 22 to a management CIDR.
- **Absence of data is not absence of risk.** If `sshd -T` was unavailable and only the config file was read, note reduced confidence (Match-block overrides unresolved).
- **Sort the report** by severity: critical → high → medium → low → info.
