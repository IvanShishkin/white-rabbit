# Checks — cross-surface correlation (`cross_correlation` section)

Produced by `scripts/analyze/correlate.sh` from the SSH-auth dump and the web-access dump.
Each hit is a `WR-CROSS:` line: `WR-CROSS: <ip> ssh=<roles> web=<roles> severity=<hint>`.
`ssh` roles ∈ {failed, accepted}; `web` roles ∈ {client, scanner, sensitive, login-bf, payload, ua, header}
(`payload` = flagged in path_payloads, `ua` = suspicious_user_agents, `header` = suspicious_headers). IPs are
taken from each section's fixed IP column and validated (IPv4 or IPv6), so attacker-controlled
path/UA/Host text cannot inject a phantom correlation.
The whole point: an IP active on **both** surfaces is a far stronger signal than the same IP
on either alone — a single collector cannot see this. Treat the script's `severity=` as a
starting hint and adjust with the surrounding evidence.

### Foothold IP also active on the web
- **id:** xcorr-foothold-plus-web
- **severity:** critical
- **look for:** a `WR-CROSS:` line with `ssh=…accepted…` (an accepted SSH login) and any `web=` role.
- **why:** The IP already has (or had) an authenticated SSH session on the host AND is generating attack-shaped web traffic. Either the operator's own IP is also scanning (unlikely/benign — verify) or an attacker with a foothold is also probing the application. Combined with a sensitive-file 2xx or an SSH brute-force history on the same IP, assume compromise until proven otherwise.
- **fix:** `# investigate the session NOW: 'last -f /var/log/wtmp | grep <ip>', 'sudo journalctl _COMM=sshd | grep <ip>'; if not a known operator IP, rotate the credential/key it used and block it: sudo ufw deny from <ip>`
- **mitre:** T1078 (Valid Accounts) + T1190 (Exploit Public-Facing Application)

### Coordinated attacker across SSH and web
- **id:** xcorr-coordinated-attacker
- **severity:** high
- **look for:** a `WR-CROSS:` line with `ssh=…failed…` (SSH brute force) and an attack-shaped web role — `scanner`, `login-bf`, `sensitive`, `payload` (attack payload in the URL path), `ua` (scanner user-agent), or `header` (Host/Referer manipulation).
- **why:** The same source is brute-forcing SSH *and* scanning / brute-forcing / probing sensitive paths on the web app. This is a single actor working every exposed door — higher intent and persistence than an opportunistic bot hitting one service. Prioritise blocking it and hardening both surfaces.
- **fix:** `# block the source at the firewall and ensure both surfaces are rate-limited: sudo ufw deny from <ip>; verify key-only SSH + a login throttle on the web app (fail2ban jails for sshd and the access log)`
- **mitre:** T1595 (Active Scanning) + T1110 (Brute Force)

### Same IP present on both surfaces
- **id:** xcorr-shared-presence
- **severity:** medium
- **look for:** a `WR-CROSS:` line whose roles don't meet the two cases above (e.g. `ssh=failed web=client`).
- **why:** A shared source across surfaces is worth noting — it can be an early-stage actor or a shared NAT/CDN egress. Correlate with volume and the per-surface findings before escalating; a busy `client` role alone may be benign.
- **fix:** `# review the IP's activity in both the log-hunt and web-hunt reports; block only if the per-surface evidence warrants it — a bare shared presence is a lead, not a verdict`
- **mitre:** T1590 (Gather Victim Network Information)
