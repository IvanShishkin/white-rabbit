# Checks — SSH configuration (`ssh_config` section of the snapshot)

Read the effective config from the `ssh_config` section. Keys come from
`sshd -T` (lowercased keys) or the raw `sshd_config` file. If only the file was
read, Match-block overrides are NOT resolved — lower confidence accordingly.

### Root login permitted
- **id:** ssh-permit-root-login
- **severity:** high
- **look for:** `permitrootlogin yes` (or `without-password`/`prohibit-password` = partial)
- **why:** Direct root login over SSH removes an accountability and brute-force barrier; a single credential leak is full compromise.
- **fix:** `# in /etc/ssh/sshd_config set 'PermitRootLogin no' (uncomment or add the line), then: sudo systemctl reload ssh`

### Password authentication enabled
- **id:** ssh-password-auth
- **severity:** high
- **look for:** `passwordauthentication yes`
- **why:** Enables online brute-force/credential-stuffing. Key-only auth eliminates the entire class. Severity is *medium* if the firewall restricts port 22 to a trusted CIDR (see firewall/ports sections).
- **fix:** `# ensure your key works first, then set PasswordAuthentication no in /etc/ssh/sshd_config and: sudo systemctl reload ssh`

### Empty passwords permitted
- **id:** ssh-permit-empty-passwords
- **severity:** critical
- **look for:** `permitemptypasswords yes`
- **why:** Any account with an empty password is logged in without a credential — trivial full access.
- **fix:** `# set PermitEmptyPasswords no in /etc/ssh/sshd_config and: sudo systemctl reload ssh`

### Legacy protocol / weak algorithms
- **id:** ssh-weak-algorithms
- **severity:** medium
- **look for:** weak entries in `ciphers`/`macs`/`kexalgorithms` (e.g. `arcfour`, `3des-cbc`, `hmac-md5`, `diffie-hellman-group1-sha1`). (Legacy `Protocol 1` was removed in OpenSSH 7.6 and will not appear in `sshd -T`.)
- **why:** Deprecated crypto is vulnerable to known attacks (downgrade, collision, weak key exchange).
- **fix:** `# restrict to modern algorithms (Ciphers/MACs/KexAlgorithms) in /etc/ssh/sshd_config and: sudo systemctl reload ssh`

### X11 forwarding enabled
- **id:** ssh-x11-forwarding
- **severity:** low
- **look for:** `x11forwarding yes`
- **why:** Expands the attack surface from a compromised client back to the server's X session; rarely needed on a server.
- **fix:** `# set X11Forwarding no in /etc/ssh/sshd_config and: sudo systemctl reload ssh`
