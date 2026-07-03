# Checks — HTTP access logs (web_pull.sh dump sections)

Apply to the aggregated dump (nginx combined or Caddy JSON, both normalized to the same
`ip method path status bytes ua referer host` contract before aggregation). The KEY correlation:
cross `sensitive_path_hits` against its status column — a **2xx** on a sensitive path (`/.env`,
`/.git/config`, a backup/dump, `/phpinfo`, `/server-status`) means the file was actually served,
not just probed. That is a confirmed exposure, not a scan.

### Sensitive file actually served (2xx)
- **id:** web-sensitive-file-exposed
- **severity:** critical
- **look for:** a `sensitive_path_hits` line whose status is 2xx (e.g. `200 /.env <ip>`, `200 /.git/config <ip>`, `200 backup.sql <ip>`, `200 /phpinfo.php <ip>`).
- **why:** The file was retrieved successfully — this is a confirmed data exposure (source, config, credentials, dumps), not an attempted or blocked probe. Treat it like a successful login after brute-force: assume the attacker now has the contents.
- **fix:** `# take it down now: verify why the path is web-reachable, remove it from the webroot or block it at the server/proxy config, then ROTATE every credential/secret found inside the exposed file`
- **mitre:** T1190 (Exploit Public-Facing Application) + T1552 (Unsecured Credentials)

### Attack payload in the request path (traversal / SQLi / XSS / RCE probe)
- **id:** web-path-payload
- **severity:** high (raise to critical if the status is 2xx — a served payload path may be a successful exploit)
- **look for:** a `path_payloads` line: `<count> <ip> <status> <path>` where the path carries an attack signature — directory traversal (`../`, `%2e%2e`), SQLi (`union select`), XSS (`<script`), local-file inclusion (`/etc/passwd`), Log4Shell (`${jndi:`), or `base64_decode`. Check the status: a **2xx** means the payload path was served (possible successful exploit); a **4xx** is a blocked/failed probe (still reconnaissance worth noting). Also glance at `notable_5xx` and `evidence` for payloads that errored.
- **why:** Payloads in the URL path are direct exploitation or reconnaissance attempts — traversal reads files outside the webroot (`/etc/passwd`, secrets, source), SQLi/XSS/Log4Shell target the app directly. A 2xx here is far more urgent than a blocked probe.
- **fix:** `# patch/upgrade the app; add input normalization + payload rejection at the reverse proxy/WAF (nginx: reject requests whose URI contains "../", "union select", "${jndi:" etc. before they reach the upstream). If any payload path returned 2xx, treat it as a possible breach and investigate what was served.`
- **mitre:** T1190 (Exploit Public-Facing Application)

### Login endpoint brute force
- **id:** web-login-bruteforce
- **severity:** high
- **look for:** a `login_bruteforce` line with a high `<count>` of POSTs to a login endpoint and a high `<fail_count>` (401/403), e.g. `5 198.51.100.30 /wp-login.php 5`.
- **why:** Sustained credential guessing against a login form; if it eventually succeeds, it is a breach — the same "success after failures" pattern as SSH brute force.
- **fix:** `# add rate-limiting/lockout on the login endpoint (fail2ban jail on the access log, or app-level throttle) and enforce strong passwords / MFA`
- **mitre:** T1110 (Brute Force)

### Vulnerability/content scanning
- **id:** web-vuln-scanning
- **severity:** medium
- **look for:** a `top_scanning_sources` line with a high `<count_4xx>` spread across many `<distinct_paths>` from one IP, e.g. `6 6 198.51.100.20`.
- **why:** Automated scanning for hidden files/endpoints/vulnerabilities routinely precedes a targeted exploitation attempt.
- **fix:** `# block or rate-limit the scanning IP at the firewall/WAF: sudo ufw deny from <ip>`
- **mitre:** T1595 (Active Scanning)

### Admin/login-panel probing
- **id:** web-admin-probe
- **severity:** medium
- **look for:** `sensitive_path_hits` or scanning activity concentrated on admin/login surface paths (`/admin`, `/administrator`, `/phpmyadmin`, `/wp-login.php`, `/user/login`).
- **why:** Probing for management interfaces is reconnaissance ahead of a follow-on credential attack or exploit against an admin panel.
- **fix:** `# restrict admin/management paths to a management CIDR or VPN, and/or move them off their default, predictable path`
- **mitre:** T1595 (Active Scanning)

### 5xx spike on a path
- **id:** web-5xx-spike
- **severity:** medium
- **look for:** a `notable_5xx` line with an unusually high `<count>` for one `<path>`, or the `status_daily` aggregate showing a disproportionate `5xx=` count relative to total traffic.
- **why:** A spike of server errors concentrated on one path can indicate a crash-inducing exploitation attempt (malformed input, DoS) rather than an ordinary application bug.
- **fix:** `# check application/server logs for stack traces tied to this path and time window; patch the handler or add input validation`
- **mitre:** T1190 (Exploit Public-Facing Application)

### Suspicious user-agent
- **id:** web-suspicious-user-agent
- **severity:** medium
- **look for:** a `suspicious_user_agents` line naming a known scanner tool (`sqlmap`, `nikto`, `nmap`, `masscan`, `wpscan`, `dirbuster`/`gobuster`, `nuclei`, `acunetix`, `zgrab`), a bare scripted HTTP client (`curl/`, `Wget/`, `python-requests`, `Go-http-client`, `libwww`, `okhttp`), or an empty/very short UA.
- **why:** These clients are rarely legitimate browser traffic; correlate the UA with the paths/status codes it produced (in `sensitive_path_hits` / `top_scanning_sources`) for confidence before acting.
- **fix:** `# if confirmed malicious (correlated with scanning/exposure), block by UA+IP at the reverse proxy or WAF — do not block on UA alone, it is trivially spoofed`
- **mitre:** T1595 (Active Scanning)

### Header anomaly (Host/Referer)
- **id:** web-header-anomaly
- **severity:** medium
- **look for:** a `suspicious_headers` line of kind `host-mismatch` or `host-is-ip` (request Host doesn't match the expected domain, or is a bare IP), or `referer-payload`/`host-payload` (a traversal/injection signature inside Referer or Host).
- **why:** Host-header manipulation can bypass virtual-host routing, poison caches, or exploit code that trusts the Host header (e.g. password-reset link generation); payloads in Referer/Host are usually automated probing.
- **fix:** `# enforce a strict allow-list of expected Host headers at the reverse proxy/server config; reject requests carrying an unrecognized Host`
- **mitre:** T1190 (Exploit Public-Facing Application)
