# Checks — patch level (`patching` section)

Read the `patching` section: `reboot_required:`, the apt/dnf upgradable list, and the
`distro:` line. Absence of the pending-update list (no apt/dnf, or need root) lowers
confidence — note it rather than reporting "up to date."

### End-of-life distribution release
- **id:** patch-eol-distro
- **severity:** high
- **look for:** a `distro:` line naming a release past its support window (e.g. Ubuntu non-LTS older than 9 months, an Ubuntu LTS past 5 years without ESM, Debian past EOL, CentOS 7/8). Use your knowledge of current support dates for the collected release.
- **why:** An EOL release no longer receives security updates — known vulnerabilities in the base OS stay unpatched forever. This is one of the most common real findings on neglected hosts.
- **fix:** `# plan an OS upgrade to a supported release; as a stopgap on Ubuntu LTS, enable ESM: sudo pro attach / sudo ua enable esm-infra`

### Pending security updates
- **id:** patch-pending-security
- **severity:** high
- **look for:** entries in the apt/dnf upgradable list flagged `security` (Ubuntu marks these `…-security`), especially for network-facing packages (openssl, openssh-server, nginx, the kernel).
- **why:** A published security update means the vulnerability it fixes is public; an unpatched internet-facing service is directly exploitable.
- **fix:** `# apply security updates: sudo apt-get update && sudo apt-get upgrade  (or, security-only: sudo unattended-upgrade --dry-run then without --dry-run)`

### Reboot required (new kernel/libs not yet running)
- **id:** patch-reboot-required
- **severity:** medium
- **look for:** `reboot_required: yes`, with `reboot_required_pkgs:` listing e.g. `linux-image-*` or `libssl`.
- **why:** A patched kernel or shared library is installed but the old, vulnerable one is still in memory until reboot — the fix isn't actually in effect. Long uptime with a kernel update pending is a real exposure window.
- **fix:** `# schedule a reboot during a maintenance window: sudo shutdown -r +5 'security reboot'  (check what needs it first: cat /var/run/reboot-required.pkgs)`

### No automatic security updates
- **id:** patch-no-unattended-upgrades
- **severity:** low
- **look for:** the upgradable list shows security updates accumulating and there is no sign of `unattended-upgrades` keeping the host current (many pending security items on a host that should be low-touch).
- **why:** Without automated patching, security fixes land only when someone remembers — the window between disclosure and patch stays open longer than it needs to.
- **fix:** `# enable automatic security updates: sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`
