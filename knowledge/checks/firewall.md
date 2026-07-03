# Checks — firewall (`firewall` section of the snapshot)

The section may contain `WR-TOOL: ufw|iptables|nft` blocks, or a
`WR-NOTE: no firewall tool present`. Interpret the first tool that shows an
active policy; ufw is a front-end to iptables, so treat ufw's view as authoritative when present.

### No active firewall
- **id:** fw-none-active
- **severity:** high
- **look for:** `WR-NOTE: no firewall tool present`; or `ufw status` = `inactive`; or iptables policy `ACCEPT` on all chains with no rules; or empty `nft list ruleset`.
- **why:** With no firewall, every listening service is reachable from anywhere it routes — the listening-ports findings become directly exploitable.
- **fix:** `# replace 22 with the actual SSH port from the listening section, then: sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw enable`

### Default-allow inbound policy
- **id:** fw-default-allow-inbound
- **severity:** high
- **look for:** ufw `Default: allow (incoming)`; or iptables `Chain INPUT (policy ACCEPT)` with no deny rules.
- **why:** A default-allow inbound policy means anything not explicitly blocked is open — the opposite of least privilege.
- **fix:** `# allow your SSH port FIRST to avoid lockout (replace 22 with the port from the listening section): sudo ufw allow 22/tcp && sudo ufw default deny incoming`

### Sensitive port open to the world
- **id:** fw-sensitive-port-world-open
- **severity:** high
- **look for:** an `allow`/`ACCEPT` rule for `0.0.0.0/0` (or `::/0`, or `Anywhere`) to a sensitive port from the ports catalog (e.g. 22, 3306, 5432, 6379, 27017).
- **why:** Exposing management/database ports to the whole internet invites brute-force and direct exploitation.
- **fix:** `# restrict the rule to a trusted source CIDR, e.g.: sudo ufw allow from <your.ip>/32 to any port 22 proto tcp`
