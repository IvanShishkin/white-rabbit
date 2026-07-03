# Checks — accounts & access (`users_auth`, `sudoers`, `authorized_keys` sections)

Answers "who can log in, and who can become root." Cross these against the log-hunt
`accepted_logins` when both are available — a fresh key or a NOPASSWD account that also
appears in the auth log is a stronger signal.

### Second UID-0 account (root-equivalent backdoor)
- **id:** access-uid0-duplicate
- **severity:** critical
- **look for:** more than one `uid0:` line in `users_auth` (anything other than a lone `uid0: root`).
- **why:** A non-root account with UID 0 has full root privileges and is a classic persistence backdoor — it survives a root password change and is easy to miss.
- **fix:** `# identify the account and remove/relock it: 'sudo passwd -l <user>' then investigate how it was created; verify with: awk -F: '$3==0' /etc/passwd`
- **mitre:** T1136 (Create Account) + T1078.003 (Local Accounts)

### Account with an empty password
- **id:** access-empty-password
- **severity:** critical
- **look for:** any `empty_password:` line in `users_auth`.
- **why:** The account authenticates with no credential at all — trivial local (and, if `PasswordAuthentication yes`, remote) access.
- **fix:** `# lock it immediately: sudo passwd -l <user>  (or set a real password); confirm no others: sudo awk -F: '$2==""' /etc/shadow`

### Passwordless sudo (NOPASSWD)
- **id:** access-sudo-nopasswd
- **severity:** high
- **look for:** a `nopasswd_rule:` line in `sudoers`.
- **why:** The user escalates to root without re-authenticating; a compromise of that user's session (stolen SSH key, hijacked shell) is an immediate full root compromise with no password barrier.
- **fix:** `# require a password: remove NOPASSWD from the rule in /etc/sudoers or the /etc/sudoers.d file (edit with 'sudo visudo'), unless a specific automation genuinely needs it (then scope it to exact commands)`
- **mitre:** T1548.003 (Sudo and Sudo Caching)

### Docker group membership (root-equivalent)
- **id:** access-docker-group
- **severity:** high
- **look for:** a `group: docker members=...` line with any member.
- **why:** Anyone in the `docker` group can mount the host filesystem into a container and read/write it as root — membership is effectively unrestricted root, without needing sudo.
- **fix:** `# remove non-essential members: sudo gpasswd -d <user> docker ; grant Docker access via a rootless setup or scoped sudo instead`
- **mitre:** T1548 (Abuse Elevation Control Mechanism)

### Unexpected SSH key / freshly added key
- **id:** access-authorized-key-review
- **severity:** medium
- **look for:** an `authorized_keys:` line for an account you did not expect to have keys, a `keys=` count higher than you manage, or an `mtime=` that is recent on an otherwise-stable host. Cross the `key:` comment against known devices.
- **why:** An added `authorized_keys` entry is the quietest SSH persistence mechanism — it survives password rotation and rarely shows up in a config audit. On a key-only host the keyset *is* the access-control list.
- **fix:** `# review each key and remove any you don't recognize from the user's ~/.ssh/authorized_keys; rotate if in doubt. Confirm owner: last -f /var/log/wtmp`
- **mitre:** T1098.004 (SSH Authorized Keys)

### Service account with a login shell
- **id:** access-service-account-shell
- **severity:** low
- **look for:** a `shell_user:` line for a system/service account (e.g. `www-data`, `postgres`, `redis`) pointing at a real shell (`/bin/bash`, `/bin/sh`) rather than `nologin`/`false`.
- **why:** Service accounts rarely need an interactive shell; one present widens the blast radius if that service is compromised (the attacker gets a usable shell).
- **fix:** `# set the account's shell to nologin: sudo usermod -s /usr/sbin/nologin <user>  (confirm nothing legitimately logs in as it first)`
