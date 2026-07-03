# Checks — SSH/auth logs (log_pull.sh dump sections)

Apply to the aggregated dump. The KEY correlation: cross `accepted_logins` against
`top_failed_sources` / `top_invalid_users` — a success from an attacker IP is a possible breach.

`accepted_logins` lines are deduped as `<count> <user> <ip> <method>` (most frequent first). A high
`<count>` means a busy/automated source; a low `<count>` is NOT low-risk — a single `root` or a lone
login from an attacker IP is exactly what to look for. Match by user/IP/method, not by count.

### Successful login from a brute-forcing source
- **id:** auth-login-after-bruteforce
- **severity:** critical
- **look for:** an `accepted_logins` line whose IP also appears in `top_failed_sources`, OR whose user appears in `top_invalid_users`.
- **why:** A successful authentication from an IP that was hammering the host with failed attempts is a strong breach indicator — the attacker may have guessed/obtained a credential or key.
- **fix:** `# investigate NOW: who is that session? check 'last -f /var/log/wtmp' and 'sudo journalctl _COMM=sshd | grep <ip>'; rotate the affected credential/key and block the IP: sudo ufw deny from <ip>`
- **mitre:** T1078 (Valid Accounts) + T1110 (Brute Force)

### High-volume brute force from a single IP
- **id:** auth-bruteforce-single-ip
- **severity:** high
- **look for:** a `top_failed_sources` IP with a large failure count (e.g. > 100 in the window).
- **why:** Sustained online password guessing against the host; even if unsuccessful so far, it is active attack traffic and noise that can hide a real hit.
- **fix:** `# block the IP and add brute-force protection: sudo ufw deny from <ip> ; and install fail2ban (see auth-no-bruteforce-defense)`
- **mitre:** T1110 (Brute Force)

### Distributed brute force / username spraying
- **id:** auth-bruteforce-distributed
- **severity:** medium
- **look for:** many distinct `top_failed_sources` IPs each with modest counts, and/or `top_invalid_users` dominated by common names (root, admin, oracle, test, ubuntu).
- **why:** A botnet spraying credentials from many IPs evades single-IP bans; the username list reveals what they target.
- **fix:** `# enforce key-only auth (PasswordAuthentication no) and install a rate-limiter (fail2ban/crowdsec)`
- **mitre:** T1110.001 (Password Guessing)

### Direct root login accepted
- **id:** auth-root-login
- **severity:** medium
- **look for:** an `accepted_logins` line with user `root`.
- **why:** Direct root SSH removes accountability; combined with any brute-force it is high-risk.
- **fix:** `# set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl reload ssh`
- **mitre:** T1078.003 (Local Accounts)

### No brute-force defense while under attack
- **id:** auth-no-bruteforce-defense
- **severity:** medium
- **look for:** the `defenses` section shows `fail2ban: NOT installed` AND `crowdsec: NOT installed`, while `top_failed_sources` shows active brute force.
- **why:** Nothing is auto-blocking attackers; failures will continue indefinitely and increase breach odds.
- **fix:** `# install a rate-limiter, e.g.: sudo apt-get install fail2ban && sudo systemctl enable --now fail2ban  (ships with an sshd jail)`
- **mitre:** M1036 (Account Use Policies)

### Off-hours or unexpected successful login
- **id:** auth-off-hours-login
- **severity:** low
- **look for:** an accepted login from an unexpected network for this host's normal pattern (use the IP in `accepted_logins`), or at an unusual hour — read the timestamps from the raw `Accepted` lines in the `evidence` section, since `accepted_logins` is deduped and carries no times.
- **why:** Legitimate operators have patterns; a success far outside them warrants a look.
- **fix:** `# confirm the login was expected; if not, treat as auth-login-after-bruteforce`
- **mitre:** T1078 (Valid Accounts)
